import mongoose from 'mongoose'
import { IRefreshToken } from '../types/user.types'
import config from '../config/config'

const tokenSchema = new mongoose.Schema<IRefreshToken>(
    {
        token: {
            type: String,
            required: true
        }
    },
    {
        timestamps: true
    }
)

tokenSchema.index(
    {
        createdAt: -1
    },
    {
        expireAfterSeconds: config.REFRESH_TOKEN.EXPIRY
    }
)

export default mongoose.model<IRefreshToken>('refresh-token', tokenSchema)
