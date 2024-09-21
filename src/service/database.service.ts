import mongoose from 'mongoose'
import config from '../config/config'
import userModel from '../models/user.model'
import { IRefreshToken, IUser } from '../types/user.types'
import tokenModel from '../models/token.model'

export default {
    connect: async () => {
        try {
            await mongoose.connect(config.DATABASE_URL as string)
            return mongoose.connection
        } catch (err) {
            throw err
        }
    },
    findUserByEmailAddress: (emailAddress: string, select: string = '') => {
        return userModel
            .findOne({
                emailAddress
            })
            .select(select)
    },
    registerUser: (payload: IUser) => {
        return userModel.create(payload)
    },
    findUserByConfirmationTokenAndCode: (token: string, code: string) => {
        return userModel.findOne({
            'accountConfirmation.token': token,
            'accountConfirmation.code': code
        })
    },
    createRefreshToken: (token: IRefreshToken) => {
        return tokenModel.create(token)
    }
}
