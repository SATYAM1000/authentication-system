import mongoose from 'mongoose'
import { IRefreshToken } from '../types/user.types'

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

export default mongoose.model<IRefreshToken>('refresh-token', tokenSchema)
