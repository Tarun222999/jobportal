const { createPostSchema } = require('../middlewares/validator');
const Post = require('../models/postsModel');
const nodemailer = require('nodemailer');

// Function to send email alerts to candidates
const sendEmailAlerts = async (candidates, jobDetails, companyName) => {
	// Create a transporter object using SMTP transport
	const transporter = nodemailer.createTransport({
		service: 'gmail', // Use your email service (e.g., Gmail)
		auth: {
			user: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS, // Your email
			pass: process.env.NODE_CODE_SENDING_EMAIL_PASSWORD,    // Your email password (or an App Password)
		},
	});

	// Email content
	const mailOptions = {
		from: 'your-email@gmail.com',
		to: candidates, // List of candidates' email addresses
		subject: `New Job Alert: ${jobDetails.title}`,
		text: `
      Hello,

      We are excited to inform you about a new job opening!

      Job Title: ${jobDetails.title}
      Description: ${jobDetails.description}
      Experience Level: ${jobDetails.expLvl}
      End Date: ${jobDetails.endDate}

      For more details, please visit our website or reply to this email.

      Best Regards,
      ${companyName}
    `,
	};

	try {
		// Send the email
		await transporter.sendMail(mailOptions);
		console.log('Email sent successfully to candidates:', candidates);
	} catch (error) {
		console.error('Error sending email:', error);
	}
};


exports.getPosts = async (req, res) => {
	const { page } = req.query;
	const postsPerPage = 10;

	try {
		let pageNum = 0;
		if (page <= 1) {
			pageNum = 0;
		} else {
			pageNum = page - 1;
		}
		const result = await Post.find()
			.sort({ createdAt: -1 })
			.skip(pageNum * postsPerPage)
			.limit(postsPerPage)
			.populate({
				path: 'userId',
				select: 'email',
			});
		res.status(200).json({ success: true, message: 'posts', data: result });
	} catch (error) {
		console.log(error);
	}
};

exports.singlePost = async (req, res) => {
	const { _id } = req.query;

	try {
		const existingPost = await Post.findOne({ _id }).populate({
			path: 'userId',
			select: 'email',
		});
		if (!existingPost) {
			return res
				.status(404)
				.json({ success: false, message: 'Post unavailable' });
		}
		res
			.status(200)
			.json({ success: true, message: 'single post', data: existingPost });
	} catch (error) {
		console.log(error);
	}
};

exports.createPost = async (req, res) => {
	console.log(req.user)
	const { title, description, expLvl, candidates, endDate } = req.body;
	const { userId } = req.user;
	try {
		const { error, value } = createPostSchema.validate({
			title,
			description,
			userId,
			expLvl,
			candidates,
			endDate
		});
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}

		const result = await Post.create({
			title,
			description,
			userId,
			expLvl,
			candidates,
			endDate
		});

		await sendEmailAlerts(candidates, { title, description, expLvl, endDate }, req.user.companyName);
		res.status(201).json({ success: true, message: 'created', data: result });
	} catch (error) {
		console.log(error);
	}
};

exports.updatePost = async (req, res) => {
	const { _id } = req.query;
	const { title, description } = req.body;
	const { userId } = req.user;
	try {
		const { error, value } = createPostSchema.validate({
			title,
			description,
			userId,
		});
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}
		const existingPost = await Post.findOne({ _id });
		if (!existingPost) {
			return res
				.status(404)
				.json({ success: false, message: 'Post unavailable' });
		}
		if (existingPost.userId.toString() !== userId) {
			return res.status(403).json({ success: false, message: 'Unauthorized' });
		}
		existingPost.title = title;
		existingPost.description = description;

		const result = await existingPost.save();
		res.status(200).json({ success: true, message: 'Updated', data: result });
	} catch (error) {
		console.log(error);
	}
};

exports.deletePost = async (req, res) => {
	const { _id } = req.query;

	const { userId } = req.user;
	try {
		const existingPost = await Post.findOne({ _id });
		if (!existingPost) {
			return res
				.status(404)
				.json({ success: false, message: 'Post already unavailable' });
		}
		if (existingPost.userId.toString() !== userId) {
			return res.status(403).json({ success: false, message: 'Unauthorized' });
		}

		await Post.deleteOne({ _id });
		res.status(200).json({ success: true, message: 'deleted' });
	} catch (error) {
		console.log(error);
	}
};
