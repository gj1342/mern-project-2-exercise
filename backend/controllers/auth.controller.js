import User from "../models/user.model.js";
import bcrypt from "bcrypt";

import { generateTokenAndSetCookie } from "../lib/utils/generateToken.js";

export const signup = async (req, res) => {
    try{
        const { fullName, username, email, password } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Invalid email address" });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Username already exists" });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ message: "Email already exists" });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ message: "Password must be at least 6 characters long" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            fullName,
            username,
            email,
            password: hashedPassword
        });
        
        if (newUser) {
            generateTokenAndSetCookie(res, newUser._id);
            await newUser.save();
            res.status(201).json({ 
                _id: newUser._id, 
                fullName: newUser.fullName, 
                username: newUser.username, 
                email: newUser.email,
                followers: newUser.followers,
                following: newUser.following,
                profilePicture: newUser.profilePicture,
                coverPicture: newUser.coverPicture,
            });
        }else{
            res.status(400).json({ message: "Invalid user data" });
        }

    } catch (error) {
        console.log("Error in signup controller:", error);
        res.status(500).json({ message: error.message });
    }
};

export const login = async (req, res) => {
    try{
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        const isPasswordCorrect = await bcrypt.compare(password, user?.password || "");

        if(!user || !isPasswordCorrect){
            return res.status(400).json({ message: "Invalid username or password" });
        }

        generateTokenAndSetCookie(res, user._id);

        res.status(200).json({ 
            _id: user._id, 
            fullName: user.fullName, 
            username: user.username, 
            email: user.email,
            followers: user.followers,
            following: user.following,
            profilePicture: user.profilePicture,
            coverPicture: user.coverPicture,
        });
            
    } catch (error) {
        console.log("Error in login controller:", error);
        res.status(500).json({ message: error.message });
    }
};

export const logout = async (req, res) => {
    try{
        res.cookie("jwt", "", { maxAge: 0 });
        res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
        console.log("Error in logout controller:", error);
        res.status(500).json({ message: error.message });
    }
};

export const getMe = async (req, res) => {
    try{
        const user = await User.findById(req.user._id).select("-password");
        res.status(200).json(user);
    } catch (error) {
        console.log("Error in getMe controller:", error);
        res.status(500).json({ message: error.message });
    }
};