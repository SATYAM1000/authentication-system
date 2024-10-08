import { NextFunction, Request, Response } from 'express'
import httpResponse from '../util/httpResponse'
import responseMessage from '../constant/responseMessage'
import httpError from '../util/httpError'
import quicker from '../util/quicker'
import {
    IChangePasswordRequestBody,
    IForgotRequestBody,
    ILoginRequestBody,
    IRefreshToken,
    IRegisterRequestBody,
    IResetPasswordRequestBody,
    IUser,
    IUserWithId
} from '../types/user.types'
import {
    validateChangePasswordBody,
    validateForgotPasswordBody,
    validateJoiSchema,
    validateLoginBody,
    validateRegisterBody,
    validateResetPasswordBody
} from '../validation/auth'
import databaseService from '../service/database.service'
import { EUserRole } from '../constant/user.constant'
import config from '../config/config'
import emailService from '../service/email.service'
import logger from '../util/logger'
import utc from 'dayjs/plugin/utc'
import dayjs from 'dayjs'
import { EApplicationEnvironment } from '../constant/application'
import { JwtPayload } from 'jsonwebtoken'

dayjs.extend(utc)

interface IRegisterRequest extends Request {
    body: IRegisterRequestBody
}

interface IConfirmRequest extends Request {
    params: {
        token: string
    }
    query: {
        code: string
    }
}

interface ILoginRequest extends Request {
    body: ILoginRequestBody
}

interface IDecryptedJwt extends JwtPayload {
    userId: string
}

interface IForgotPasswordRequest extends Request {
    body: IForgotRequestBody
}

interface IResetPasswordRequest extends Request {
    params: {
        token: string
    }
    body: IResetPasswordRequestBody
}

interface IChangePasswordRequest extends Request {
    authenticatedUser: IUserWithId
    body: IChangePasswordRequestBody
}

export default {
    self: (req: Request, res: Response, next: NextFunction) => {
        try {
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    health: (req: Request, res: Response, next: NextFunction) => {
        try {
            const healthData = {
                application: quicker.getApplicationHealth(),
                system: quicker.getSystemHealth(),
                timestamp: Date.now()
            }

            httpResponse(req, res, 200, responseMessage.SUCCESS, healthData)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    register: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { body } = req as IRegisterRequest

            const { error, value } = validateJoiSchema<IRegisterRequestBody>(validateRegisterBody, body)
            if (error) {
                return httpError(next, error, req, 422)
            }

            const { name, consent, emailAddress, phoneNumber, password } = value

            const { countryCode, internationalNumber, isoCode } = quicker.parsePhoneNumber('+' + phoneNumber)

            if (!countryCode || !internationalNumber || !isoCode) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422)
            }

            const timezone = quicker.countryTimeZone(isoCode)
            if (!timezone || timezone.length === 0) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422)
            }

            const user = await databaseService.findUserByEmailAddress(emailAddress)
            if (user) {
                return httpError(next, new Error(responseMessage.ALREADY_EXISTS('user', emailAddress)), req, 422)
            }

            const encryptedPassword = await quicker.hashPassword(password)
            const token = quicker.generateRandomId()
            const code = quicker.generateOTP(6)

            const payload: IUser = {
                name,
                emailAddress,
                phoneNumber: {
                    countryCode,
                    isoCode,
                    internationalNumber
                },
                accountConfirmation: {
                    status: false,
                    token,
                    code,
                    timestamp: null
                },
                passwordReset: {
                    token: null,
                    expiry: null,
                    lastResetAt: null
                },
                lastLoginAt: null,
                role: EUserRole.USER,
                timezone: timezone[0].name,
                password: encryptedPassword,
                consent
            }

            const newUser = await databaseService.registerUser(payload)

            const confirmationURL = `${config.FRONTEND_URL}/confirmation/${token}?code=${code}`
            const to = [emailAddress]
            const subject = 'Confirm your account'
            const text = `Hey ${name}!\n\nPlease confirm your account by clicking on the link below:\n\n${confirmationURL}`
            await emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error(`EMAIL_ERROR`, {
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
                    meta: err
                })
            })

            httpResponse(req, res, 201, responseMessage.SUCCESS, {
                _id: newUser._id
            })
        } catch (error) {
            httpError(next, error, req, 500)
        }
    },
    confirmation: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { params, query } = req as IConfirmRequest

            const user = await databaseService.findUserByConfirmationTokenAndCode(params.token, query.code)
            if (!user) {
                return httpError(next, new Error(responseMessage.INVALID_ACCOUNT_CONFIRMATION_TOKEN_OR_CODE), req, 422)
            }

            if (user.accountConfirmation.status) {
                return httpError(next, new Error(responseMessage.ALREADY_CONFIRMED), req, 422)
            }

            user.accountConfirmation.status = true
            user.accountConfirmation.timestamp = dayjs().utc().toDate()
            await user.save()

            const to = [user.emailAddress]
            const subject = 'Account Confirmed'
            const text = `Hey ${user.name}!\n\nYour account has been confirmed.`
            await emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error(`EMAIL_ERROR`, {
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
                    meta: err
                })
            })

            httpResponse(req, res, 200, responseMessage.SUCCESS, {
                token: params.token,
                code: query.code
            })
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    login: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { body } = req as ILoginRequest

            const { error, value } = validateJoiSchema<ILoginRequestBody>(validateLoginBody, body)
            if (error) {
                return httpError(next, error, req, 422)
            }

            const { emailAddress } = value
            // find user
            const user = await databaseService.findUserByEmailAddress(emailAddress, '+password')
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 422)
            }

            // validate password
            const isValidPassword = await quicker.comparePassword(value.password, user.password)
            if (!isValidPassword) {
                return httpError(next, new Error(responseMessage.INVALID_EMAIL_OR_PASSWORD), req, 400)
            }
            // access token and refresh token
            const accessToken = quicker.generateToken(
                { userId: user._id },
                config.ACCESS_TOKEN.ACCESS_TOKEN_SECRET as string,
                config.ACCESS_TOKEN.EXPIRY
            )
            const refreshToken = quicker.generateToken(
                { userId: user._id },
                config.REFRESH_TOKEN.REFRESH_TOKEN_SECRET as string,
                config.REFRESH_TOKEN.EXPIRY
            )
            // update last login details
            user.lastLoginAt = dayjs().utc().toDate()
            await user.save()
            const refreshTokenPayload: IRefreshToken = {
                token: refreshToken
            }
            await databaseService.createRefreshToken(refreshTokenPayload)
            // cookie send
            const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL as string)

            res.cookie('accessToken', accessToken, {
                httpOnly: true,
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT),
                maxAge: config.ACCESS_TOKEN.EXPIRY * 1000
            }).cookie('refreshToken', refreshToken, {
                httpOnly: true,
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT),
                maxAge: config.REFRESH_TOKEN.EXPIRY * 1000
            })
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    selfIdentification: (req: Request, res: Response, next: NextFunction) => {
        try {
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    logout: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { cookies } = req
            const { refreshToken } = cookies as {
                refreshToken: string | undefined
            }
            if (refreshToken) {
                await databaseService.deleteRefreshToken(refreshToken)
            }

            //clear cookies

            const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL as string)
            res.clearCookie('accessToken', {
                httpOnly: true,
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: true,
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT),
                maxAge: config.ACCESS_TOKEN.EXPIRY * 1000
            })

            res.clearCookie('refreshToken', {
                httpOnly: true,
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: true,
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT),
                maxAge: config.REFRESH_TOKEN.EXPIRY * 1000
            })
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    refreshToken: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { cookies } = req
            const { refreshToken, accessToken } = cookies as {
                refreshToken: string | undefined
                accessToken: string | undefined
            }
            if (accessToken) {
                return httpResponse(req, res, 200, responseMessage.SUCCESS, {
                    accessToken: accessToken
                })
            }
            if (refreshToken) {
                const rft = await databaseService.findRefreshToken(refreshToken)
                if (rft) {
                    const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL as string)
                    const { userId } = quicker.verifyToken(refreshToken, config.REFRESH_TOKEN.REFRESH_TOKEN_SECRET as string) as IDecryptedJwt
                    const accessToken = quicker.generateToken(
                        { userId: userId },
                        config.ACCESS_TOKEN.ACCESS_TOKEN_SECRET as string,
                        config.ACCESS_TOKEN.EXPIRY
                    )

                    res.cookie('accessToken', accessToken, {
                        httpOnly: true,
                        path: '/api/v1',
                        domain: DOMAIN,
                        sameSite: 'strict',
                        secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT),
                        maxAge: config.ACCESS_TOKEN.EXPIRY * 1000
                    })

                    return httpResponse(req, res, 200, responseMessage.SUCCESS, {
                        accessToken
                    })
                }
            }
            httpError(next, new Error(responseMessage.UNAUTHORIZED), req, 422)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    forgotPassword: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // 1. parsing body
            const { body } = req as IForgotPasswordRequest

            // 2. validate body
            const { error, value } = validateJoiSchema<IForgotRequestBody>(validateForgotPasswordBody, body)

            if (error) {
                return httpError(next, error, req, 422)
            }

            // 3. get user
            const user = await databaseService.findUserByEmailAddress(value.emailAddress)
            // 4. check if user account is confirmed
            // eslint-disable-next-line @typescript-eslint/no-misused-promises
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404)
            }

            if (!user.accountConfirmation.status) {
                return httpError(next, new Error(responseMessage.ACCOUNT_CONFIRMATION_REQUIRED), req, 422)
            }
            // 5. generate password reset token and expiry
            const token = quicker.generateRandomId()
            const expiry = quicker.generateResetPasswordExpiry(15)
            // 6. update user
            user.passwordReset.token = token
            user.passwordReset.expiry = expiry

            await user.save()

            // 7. email address
            const resetURL = `${config.FRONTEND_URL}/reset-password/${token}`
            const to = [value.emailAddress]
            const subject = 'Reset your account'
            const text = `Hey ${user.name}!\n\nPlease click on the following link to reset your password: ${resetURL}`
            await emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error(`EMAIL_ERROR`, {
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
                    meta: err
                })
            })
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    resetPassword: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // body parsing and validation
            const { body, params } = req as IResetPasswordRequest
            const { token } = params
            const { error, value } = validateJoiSchema<IResetPasswordRequestBody>(validateResetPasswordBody, body)

            if (error) {
                return httpError(next, error, req, 422)
            }

            // fetch user by token
            const user = await databaseService.findUserByResetToken(token)
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404)
            }

            // check if user account is confirmed
            if (!user.accountConfirmation.status) {
                return httpError(next, new Error(responseMessage.ACCOUNT_CONFIRMATION_REQUIRED), req, 422)
            }
            // check url expiry
            const expiry = user.passwordReset.expiry
            if (!expiry) {
                return httpError(next, new Error(responseMessage.INVALID_REQUEST), req, 422)
            }
            const currentTimeStamp = dayjs().valueOf()

            if (currentTimeStamp > expiry) {
                return httpError(next, new Error(responseMessage.EXPIRED_RESET_PASSWORD_TOKEN), req, 422)
            }
            // hash new password
            const hashedPassword = await quicker.hashPassword(value.newPassword)

            // update user
            user.password = hashedPassword
            user.passwordReset.token = null
            user.passwordReset.expiry = null
            user.passwordReset.lastResetAt = dayjs().utc().toDate()

            await user.save()
            // email send

            const to = [user.emailAddress]
            const subject = 'Password Reset Successful'
            const text = `Hey ${user.name}!\n\nYour password has been reset successfully.`
            await emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error(`EMAIL_ERROR`, {
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
                    meta: err
                })
            })
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },
    changePassword: async (req: Request, res: Response, next: NextFunction) => {
        try {
            //body parsing
            const { body, authenticatedUser } = req as IChangePasswordRequest
            const { error, value } = validateJoiSchema<IChangePasswordRequestBody>(validateChangePasswordBody, body)

            if (error) {
                return httpError(next, error, req, 422)
            }

            // finduser by id
            const user = await databaseService.findUserById(authenticatedUser._id, '+password')
            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404)
            }
            // compare password
            const isValidPassword = await quicker.comparePassword(value.oldPassword, user.password)
            if (!isValidPassword) {
                return httpError(next, new Error(responseMessage.INVALID_PASSWORD), req, 422)
            }
            if (value.newPassword === value.oldPassword) {
                return httpError(next, new Error(responseMessage.SAME_PASSWORD), req, 422)
            }
            // password hash
            const hashedPassword = await quicker.hashPassword(value.newPassword)
            // user update
            user.password = hashedPassword
            await user.save()

            // email send
            const to = [user.emailAddress]
            const subject = 'Password Change Successful'
            const text = `Hey ${user.name}!\n\nYour password has been changed successfully.`
            await emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error(`EMAIL_ERROR`, {
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
                    meta: err
                })
            })
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    }
}
