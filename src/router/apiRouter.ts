/* eslint-disable @typescript-eslint/no-misused-promises */
import { Router } from 'express'
import apiController from '../controller/apiController'
import authentication from '../middleware/auth.middleware'

const router = Router()

router.route('/self').get(apiController.self)
router.route('/health').get(apiController.health)

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.route('/register').post(apiController.register)

// eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-misused-promises
router.route('/confirmation/:token').put(apiController.confirmation)

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.route('/login').post(apiController.login)

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.route('/self-identification').get(authentication, apiController.selfIdentification)

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.route('/logout').put(authentication, apiController.logout)

// eslint-disable-next-line @typescript-eslint/no-unsafe-argument
router.route('/refresh-token').post(apiController.refreshToken)
export default router
