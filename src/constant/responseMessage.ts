export default {
    SUCCESS: `The operation has been successful`,
    SOMETHING_WENT_WRONG: `Something went wrong!`,
    NOT_FOUND: (entity: string) => `${entity} not found`,
    TOO_MANY_REQUESTS: `Too many requests! Please try again after some time`,
    INVALID_PHONE_NUMBER: `Invalid phone number`,
    ALREADY_EXISTS: (entity: string, identifier: string) => {
        return `${entity} is already exists with ${identifier} `
    },
    INVALID_ACCOUNT_CONFIRMATION_TOKEN_OR_CODE: `Invalid account confirmation token or code`,
    ALREADY_CONFIRMED: `Already confirmed`,
    INVALID_EMAIL_OR_PASSWORD: `Invalid email or password`,
    UNAUTHORIZED: `Unauthorized access`,
    ACCOUNT_CONFIRMATION_REQUIRED: `Account confirmation required`,
    EXPIRED_RESET_PASSWORD_TOKEN: `Expired reset password token`,
    INVALID_REQUEST: `Invalid request`,
    INVALID_PASSWORD: `Invalid password`,
    SAME_PASSWORD: `Same password`
}
