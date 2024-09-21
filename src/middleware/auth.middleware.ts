import { Request, Response, NextFunction } from 'express'
import { IUser } from '../types/user.types'
import quicker from '../util/quicker'
import config from '../config/config'
import { JwtPayload } from 'jsonwebtoken'
import databaseService from '../service/database.service'
import httpError from '../util/httpError'
import responseMessage from '../constant/responseMessage'

interface IAuthenticatedRequest extends Request {
    authenticatedUser: IUser
}

interface IDecryptedJwt extends JwtPayload {
    userId: string
}

export default async (request: Request, _res: Response, next: NextFunction) => {
    try {
        const req = request as IAuthenticatedRequest
        const { cookies } = req
        const { accessToken } = cookies as Record<string, string>
        if (accessToken) {
            const { userId } = quicker.verifyToken(accessToken, config.ACCESS_TOKEN.ACCESS_TOKEN_SECRET as string) as IDecryptedJwt
            const user = await databaseService.findUserById(userId)
            if (user) {
                req.authenticatedUser = user
                return next()
            }
        }
        return httpError(next, new Error(responseMessage.UNAUTHORIZED), req, 401)
    } catch (error) {
        httpError(next, error, request, 500)
    }
}
