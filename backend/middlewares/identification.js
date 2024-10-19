const jwt = require('jsonwebtoken');
const { TokenInstance } = require('twilio/lib/rest/oauth/v1/token');

exports.identifier = (req, res, next) => {
	let token;


	if (req.headers.client === 'not-browser') {
		token = req.headers.authorization;
	} else {
		token = req.headers.authorization
	}

	if (!token) {
		return res.status(403).json({ success: false, message: 'Unauthorized' });
	}

	try {
		const userToken = token.split(' ')[1];
		const jwtVerified = jwt.verify(userToken, process.env.TOKEN_SECRET);
		if (jwtVerified) {
			req.user = jwtVerified;
			next();
		} else {
			throw new Error('error in the token');
		}
	} catch (error) {
		console.log(error);
	}
};
