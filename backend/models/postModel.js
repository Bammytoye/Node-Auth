const mongoose = require('mongoose');

const postSchema = new mongoose.Schema(
    {
        title: {
            type: String,
            required: [true, 'title is required, please'],
            trim: true,
        },

        description: {
            type: String,
            required: [true, 'description is required!'],
            trim: true,
        },

        image: {
            type: String, // URL or path to image
        },

        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },
    }, 
    
    {
        timestamps: true, // adds createdAt and updatedAt
    }
);

module.exports = mongoose.model('Post', postSchema);
