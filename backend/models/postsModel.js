const mongoose = require('mongoose');

const postSchema = mongoose.Schema(
	{
		title: {
			type: String,
			required: [true, 'title is required!'],
			trim: true,
		},
		description: {
			type: String,

			required: [true, 'description is required!'],
			trim: true,
		},
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: 'User',
			required: true,
		},

		expLvl: {
			type: String
		},

		candidates: {
			type: [String]
		},

		endDate: {
			type: String
		}
	},
	{ timestamps: true }
);

module.exports = mongoose.model('Post', postSchema);
