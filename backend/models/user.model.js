import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true 
    },
    fullName: { 
        type: String, 
        required: true 
    },
    email: { 
        type: String, 
        required: true, 
        unique: true 
    },
    password: { 
        type: String, 
        required: true, 
        minlength: 6 
    },
    followers: { 
        type: [mongoose.Schema.Types.ObjectId], 
        ref: "User", 
        default: []
    },
    following: { 
        type: [mongoose.Schema.Types.ObjectId], 
        ref: "User", 
        default: []
    },
    profilePicture: { 
        type: String, 
        default: ""
    },
    coverPicture: { 
        type: String, 
        default: ""
    },
    bio: { 
        type: String, 
        default: ""
    },
    link: { 
        type: String, 
        default: ""
    },
    likePosts:[{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Post",
        default: []
    }],
    
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

export default User;

