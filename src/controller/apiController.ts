import { NextFunction, Request, Response } from 'express'
import httpResponse from '../util/httpResponse'
import responseMessage from '../constant/responseMessage'
import httpError from '../util/httpError'
import quicker from '../util/quicker'
import { IRegisterRequestBody, IUser } from '../types/user.types'
import { validateJoiSchema, validateRegisterBody } from '../validation/auth'
import databaseService from '../service/database.service'
import { EUserRole } from '../constant/user.constant'
import config from '../config/config'
import emailService from '../service/email.service'
import logger from '../util/logger'
import utc from 'dayjs/plugin/utc'
import dayjs from 'dayjs'

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
    }
}
