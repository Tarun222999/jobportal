const jwt = require('jsonwebtoken');
const {
	signupSchema,
	signinSchema,
	acceptCodeSchema,
	changePasswordSchema,
	acceptFPCodeSchema,
} = require('../middlewares/validator');
const User = require('../models/usersModel');
const { doHash, doHashValidation, hmacProcess } = require('../utils/hashing');
const transport = require('../middlewares/sendMail');
const axios = require('axios');
const twilio = require('twilio');

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = twilio(accountSid, authToken);

exports.signup = async (req, res) => {
	const { email, password, companyName, phone, name, companySize } = req.body;
	try {
		const { error, value } = signupSchema.validate({ email, password, companyName, phone, name });
		console.log(error)
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}
		const existingUser = await User.findOne({ email });

		if (existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User already exists!' });
		}

		const hashedPassword = await doHash(password, 12);

		const newUser = new User({
			email,
			password: hashedPassword,
			companyName,
			phone,
			name
		});
		const result = await newUser.save();
		result.password = undefined;
		res.status(201).json({
			success: true,
			message: 'Your account has been created successfully',
			result,
		});
	} catch (error) {
		console.log(error);
	}
};

exports.signin = async (req, res) => {
	const { email, password } = req.body;
	try {
		const { error, value } = signinSchema.validate({ email, password });
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}

		const existingUser = await User.findOne({ email }).select('+password +mobileVerified');
		if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}
		const result = await doHashValidation(password, existingUser.password);
		if (!result) {
			return res
				.status(401)
				.json({ success: false, message: 'Invalid credentials!' });
		}
		const token = jwt.sign(
			{
				userId: existingUser._id,
				email: existingUser.email,
				verified: existingUser.verified,
				mobileVerified: existingUser.mobileVerified,
				name: existingUser.name,
				companyName: existingUser.companyName
			},
			process.env.TOKEN_SECRET,
			{
				expiresIn: '8h',
			}
		);

		res
			.cookie('Authorization', 'Bearer ' + token, {
				expires: new Date(Date.now() + 8 * 3600000),
				httpOnly: process.env.NODE_ENV === 'production',
				secure: process.env.NODE_ENV === 'production',
			})
			.json({
				success: true,
				token,
				mobileVerified: existingUser.mobileVerified,
				verified: existingUser.verified,
				name: existingUser.name,
				companyName: existingUser.companyName,
				message: 'logged in successfully',
			});
	} catch (error) {
		console.log(error);
	}
};

exports.signout = async (req, res) => {
	res
		.clearCookie('Authorization')
		.status(200)
		.json({ success: true, message: 'logged out successfully' });
};

exports.sendVerificationCode = async (req, res) => {
	const { email } = req.body;
	try {
		const existingUser = await User.findOne({ email });
		if (!existingUser) {
			return res
				.status(404)
				.json({ success: false, message: 'User does not exists!' });
		}
		if (existingUser.verified) {
			return res
				.status(400)
				.json({ success: false, message: 'You are already verified!' });
		}

		const codeValue = Math.floor(Math.random() * 1000000).toString();
		let info = await transport.sendMail({
			from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
			to: existingUser.email,
			subject: 'verification code',
			html: '<h1>' + codeValue + '</h1>',
		});

		if (info.accepted[0] === existingUser.email) {
			const hashedCodeValue = hmacProcess(
				codeValue,
				process.env.HMAC_VERIFICATION_CODE_SECRET
			);
			existingUser.verificationCode = hashedCodeValue;
			existingUser.verificationCodeValidation = Date.now();
			await existingUser.save();
			return res.status(200).json({ success: true, message: 'Code sent!' });
		}
		res.status(400).json({ success: false, message: 'Code sent failed!' });
	} catch (error) {
		console.log(error);
	}
};

exports.verifyVerificationCode = async (req, res) => {
	const { email, providedCode } = req.body;
	try {
		const { error, value } = acceptCodeSchema.validate({ email, providedCode });
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}

		const codeValue = providedCode.toString();
		const existingUser = await User.findOne({ email }).select(
			'+verificationCode +verificationCodeValidation'
		);

		if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}
		if (existingUser.verified) {
			return res
				.status(400)
				.json({ success: false, message: 'you are already verified!' });
		}

		if (
			!existingUser.verificationCode ||
			!existingUser.verificationCodeValidation
		) {
			return res
				.status(400)
				.json({ success: false, message: 'something is wrong with the code!' });
		}

		if (Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000) {
			return res
				.status(400)
				.json({ success: false, message: 'code has been expired!' });
		}

		const hashedCodeValue = hmacProcess(
			codeValue,
			process.env.HMAC_VERIFICATION_CODE_SECRET
		);

		if (hashedCodeValue === existingUser.verificationCode) {
			existingUser.verified = true;
			existingUser.verificationCode = undefined;
			existingUser.verificationCodeValidation = undefined;
			await existingUser.save();
			return res
				.status(200)
				.json({ success: true, message: 'your account has been verified!' });
		}
		return res
			.status(400)
			.json({ success: false, message: 'unexpected occured!!' });
	} catch (error) {
		console.log(error);
	}
};

exports.changePassword = async (req, res) => {
	const { userId, verified } = req.user;
	const { oldPassword, newPassword } = req.body;
	try {
		const { error, value } = changePasswordSchema.validate({
			oldPassword,
			newPassword,
		});
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}
		if (!verified) {
			return res
				.status(401)
				.json({ success: false, message: 'You are not verified user!' });
		}
		const existingUser = await User.findOne({ _id: userId }).select(
			'+password'
		);
		if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}
		const result = await doHashValidation(oldPassword, existingUser.password);
		if (!result) {
			return res
				.status(401)
				.json({ success: false, message: 'Invalid credentials!' });
		}
		const hashedPassword = await doHash(newPassword, 12);
		existingUser.password = hashedPassword;
		await existingUser.save();
		return res
			.status(200)
			.json({ success: true, message: 'Password updated!!' });
	} catch (error) {
		console.log(error);
	}
};

exports.sendForgotPasswordCode = async (req, res) => {
	const { email } = req.body;
	try {
		const existingUser = await User.findOne({ email });
		if (!existingUser) {
			return res
				.status(404)
				.json({ success: false, message: 'User does not exists!' });
		}

		const codeValue = Math.floor(Math.random() * 1000000).toString();
		let info = await transport.sendMail({
			from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
			to: existingUser.email,
			subject: 'Forgot password code',
			html: '<h1>' + codeValue + '</h1>',
		});

		if (info.accepted[0] === existingUser.email) {
			const hashedCodeValue = hmacProcess(
				codeValue,
				process.env.HMAC_VERIFICATION_CODE_SECRET
			);
			existingUser.forgotPasswordCode = hashedCodeValue;
			existingUser.forgotPasswordCodeValidation = Date.now();
			await existingUser.save();
			return res.status(200).json({ success: true, message: 'Code sent!' });
		}
		res.status(400).json({ success: false, message: 'Code sent failed!' });
	} catch (error) {
		console.log(error);
	}
};

exports.verifyForgotPasswordCode = async (req, res) => {
	const { email, providedCode, newPassword } = req.body;
	try {
		const { error, value } = acceptFPCodeSchema.validate({
			email,
			providedCode,
			newPassword,
		});
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}

		const codeValue = providedCode.toString();
		const existingUser = await User.findOne({ email }).select(
			'+forgotPasswordCode +forgotPasswordCodeValidation'
		);

		if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}

		if (
			!existingUser.forgotPasswordCode ||
			!existingUser.forgotPasswordCodeValidation
		) {
			return res
				.status(400)
				.json({ success: false, message: 'something is wrong with the code!' });
		}

		if (
			Date.now() - existingUser.forgotPasswordCodeValidation >
			5 * 60 * 1000
		) {
			return res
				.status(400)
				.json({ success: false, message: 'code has been expired!' });
		}

		const hashedCodeValue = hmacProcess(
			codeValue,
			process.env.HMAC_VERIFICATION_CODE_SECRET
		);

		if (hashedCodeValue === existingUser.forgotPasswordCode) {
			const hashedPassword = await doHash(newPassword, 12);
			existingUser.password = hashedPassword;
			existingUser.forgotPasswordCode = undefined;
			existingUser.forgotPasswordCodeValidation = undefined;
			await existingUser.save();
			return res
				.status(200)
				.json({ success: true, message: 'Password updated!!' });
		}
		return res
			.status(400)
			.json({ success: false, message: 'unexpected occured!!' });
	} catch (error) {
		console.log(error);
	}
};



exports.sendVerificationCodeMobile = async (req, res) => {
	try {
		const phone = req.body.phone;

		const otp = Math.floor(100000 + Math.random() * 900000).toString();  // Generate 6-digit OTP

		const existingUser = await User.findOne({ phone });
		if (!existingUser) {
			return res
				.status(404)
				.json({ success: false, message: 'User does not exist!' });
		}

		if (existingUser.mobileVerified) {
			return res
				.status(400)
				.json({ success: false, message: 'You are already verified!' });
		}

		// Send OTP via Twilio
		const message = await client.messages.create({
			body: `Your OTP is ${otp}`,
			from: process.env.TWILIO_PHONE_NUMBER,  // Your Twilio phone number
			to: phone
		});


		// Hash the OTP for security purposes (optional, depending on your security requirements)
		const hashedOTP = hmacProcess(otp, process.env.HMAC_VERIFICATION_CODE_SECRET);

		// Save the OTP and verification timestamp to the user's record
		existingUser.mobileverificationCode = hashedOTP;
		existingUser.mobileverificationCodeValidation = Date.now();
		await existingUser.save();

		return res.status(200).json({ success: true, message: 'OTP sent!' });

	} catch (error) {
		console.error(error);
		return res.status(500).json({ success: false, message: 'Failed to send OTP' });
	}
};


exports.verifyVerificationCodeMobile = async (req, res) => {
	try {
		const phone = req.body.phone;
		const otp = req.body.otp;  // The OTP entered by the user

		// Find the user with the provided phone number
		const existingUser = await User.findOne({ phone }).select(
			'+mobileverificationCode +mobileverificationCodeValidation +mobileVerified'
		);;
		if (!existingUser) {
			return res.status(404).json({ success: false, message: 'User does not exist!' });
		}

		// Check if the user is already verified
		if (existingUser.mobileVerified) {
			return res.status(400).json({ success: false, message: 'User is already verified!' });
		}

		// Hash the OTP entered by the user (using the same HMAC process as when sending it)
		const hashedOTP = hmacProcess(otp, process.env.HMAC_VERIFICATION_CODE_SECRET);

		// Compare the hashed OTP entered by the user with the one stored in the database
		if (existingUser.mobileverificationCode !== hashedOTP) {
			return res.status(400).json({ success: false, message: 'Invalid OTP!' });
		}

		// Optional: Check if the OTP has expired (assuming OTP expiration logic is implemented)
		const currentTime = Date.now();
		const otpTimeLimit = 10 * 60 * 1000;  // 10 minutes in milliseconds (adjust as needed)

		if (currentTime - existingUser.mobileverificationCodeValidation > otpTimeLimit) {
			return res.status(400).json({ success: false, message: 'OTP has expired!' });
		}

		// Mark the user as verified
		existingUser.mobileVerified = true;
		existingUser.mobileverificationCode = undefined;  // Clear the OTP
		existingUser.mobileverificationCodeValidation = undefined;  // Clear the validation time
		await existingUser.save();

		return res.status(200).json({ success: true, message: 'Mobile verified successfully!' });

	} catch (error) {
		console.error(error);
		return res.status(500).json({ success: false, message: 'Verification failed!' });
	}
};


exports.self = async (req, res) => {
	console.log()
	let userdetails = await User.findOne({ email: req.user.email });
	return res.status(200).json({ success: true, message: 'User Date', user: userdetails });

}