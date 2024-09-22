import joi from 'joi'
import {
    IChangePasswordRequestBody,
    IForgotRequestBody,
    ILoginRequestBody,
    IRegisterRequestBody,
    IResetPasswordRequestBody
} from '../types/user.types'

export const validateRegisterBody = joi.object<IRegisterRequestBody>({
    name: joi.string().min(2).max(72).trim().required(),
    emailAddress: joi.string().email().required(),
    phoneNumber: joi.string().min(4).max(20).required(),
    password: joi.string().min(8).max(24).required(),
    consent: joi.boolean().valid(true).required()
})

export const validateLoginBody = joi.object<ILoginRequestBody>({
    emailAddress: joi.string().email().required(),
    password: joi.string().min(8).max(24).required()
})

export const validateForgotPasswordBody = joi.object<IForgotRequestBody>({
    emailAddress: joi.string().email().required()
})

export const validateResetPasswordBody = joi.object<IResetPasswordRequestBody>({
    newPassword: joi.string().min(8).max(24).required()
})

export const validateChangePasswordBody = joi.object<IChangePasswordRequestBody>({
    oldPassword: joi.string().min(8).max(24).required(),
    newPassword: joi.string().min(8).max(24).required(),
    confirmNewPassword: joi.string().min(8).max(24).trim().valid(joi.ref('newPassword')).required()
})

export const validateJoiSchema = <T>(schema: joi.Schema, value: unknown) => {
    const result = schema.validate(value)
    return {
        value: result.value as T,
        error: result.error
    }
}
