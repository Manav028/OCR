import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import { z } from 'zod';

const signUpSchema = z.object({
  username: z.string().min(3, { message: 'Username must be at least 3 characters long' }),
  email: z.string().email({ message: 'Invalid email format' }),
  password: z.string().min(6, { message: 'Password must be at least 6 characters long' }),
});

const signInSchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }),
  password: z.string().min(6, { message: 'Password must be at least 6 characters long' }),
});

export const signUp = async (req, res) => {
  try {
  
    const { username, email, password } = signUpSchema.parse(req.body);
    
    const user = new User({ username, email, password });
    await user.save();  
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errors = error.errors.map(e => e.message);
      return res.status(400).json({ error: errors });
    }
    res.status(400).json({ error: error.message });
  }
};

export const signIn = async (req, res) => {
  try {
    const { email, password } = signInSchema.parse(req.body);
    
    const user = await User.findOne({ email });
    console.log(user)
    
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_PASS, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errors = error.errors.map(e => e.message);
      return res.status(400).json({ error: errors });
    }
    res.status(500).json({ error: error.message });
  }
};
