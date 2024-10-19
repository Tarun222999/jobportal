const express = require('express');
const authController = require('../controllers/authController');
const { identifier } = require('../middlewares/identification');
const router = express.Router();

router.post('/signup', authController.signup);
router.post('/signin', authController.signin);
router.post('/signout', identifier, authController.signout);

router.post(
	'/send-verification-code',
	identifier,
	authController.sendVerificationCode
);
router.post(
	'/verify-verification-code',
	identifier,
	authController.verifyVerificationCode
);
router.post('/change-password', identifier, authController.changePassword);
router.post(
	'/send-forgot-password-code',
	authController.sendForgotPasswordCode
);
router.post(
	'/verify-forgot-password-code',
	authController.verifyForgotPasswordCode
);


router.post(
	'/send-verification-code-mobile',
	identifier,
	authController.sendVerificationCodeMobile
);


router.post(
	'/verify-verification-code-mobile',
	identifier,
	authController.verifyVerificationCodeMobile
);


router.get(
	'/self',
	identifier,
	authController.self
);
module.exports = router;
