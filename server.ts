/// <reference path="./express.d.ts" />
import express from "express";
import type { NextFunction, Request, Response } from "express";
import "dotenv/config";
import { generateText } from "ai";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import mongoose from "mongoose";
//////////////////////////////////////////////////////////////////
dotenv.config();
const PORT = Number(process.env.PORT) || "5500";
const db = mongoose;
const app = express();
app.use(express.json());
app.use(cors());
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not defined");
}
const uriSRV = process.env.MONGO_URI;
const uriNoneSRV = process.env.MONGO_URI_NONE_SRV;
if (!uriNoneSRV) {
  throw new Error("Mongo URI is not defined");
}
// connect mongodb
db.connect(uriNoneSRV)
  .then(() => {
    console.log("✅ MongoDB connected");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection rejected:", err);
  });

//////////////////////////////////////////////////
// schema
const userSchema = new db.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  },
);

//////////////////////////////////////////////////
// model
const User = db.model("User", userSchema);

function auth(req: Request, res: Response, next: NextFunction) {
  try {
    const header = req.headers.authorization;

    console.log("Authorization Header:", header);

    if (!header) {
      return res.status(401).json({
        success: false,
        message: "No authorization header",
      });
    }

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Invalid authorization format",
      });
    }

    const token = header.split(" ")[1];

    console.log("Extracted Token:", token);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    console.log("JWT_SECRET:", JWT_SECRET);

    const decoded = jwt.verify(token, JWT_SECRET as string);

    console.log("Decoded Token:", decoded);

    req.user = decoded;

    next();
  } catch (error) {
    console.error("JWT VERIFY ERROR:");
    console.error(error);

    return res.status(401).json({
      success: false,
      message: "Invalid token",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
}
app.post("/sign-up", async (req: Request, res: Response) => {
  try {
    const { name, password, email } = req.body;

    // check if user exists
    const existingUser = await User.findOne({
      $or: [{ name: name }, { email: email }],
    });

    if (existingUser) {
      return res.status(409).json({
        message: "The user already exists",
        success: false,
      });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "User created successfully",
      success: true,
      data: user,
    });
  } catch (error: any) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      message: "Internal server error",
      success: false,
      error: error?.message,
    });
  }
});
app.get("/sign-in", async (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
  });
});

// =========================
// LOGIN ROUTE
// =========================
app.post("/sign-in", async (req: Request, res: Response) => {
  try {
    const { email, password, githubuser } = req.body;

    let user: any;
    // =========================
    // GITHUB LOGIN / SIGNUP
    // =========================
    if (githubuser?.email) {
      user = await User.findOne({ email: githubuser.email });

      if (!user) {
        user = await User.create({
          name: githubuser.username,
          email: githubuser.email,
          password: "",
        });
      }
    }

    // =========================
    // NORMAL LOGIN
    // =========================
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Missing login data",
      });
    }
    if (email && password) {
      user = await User.findOne({ email: email });

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "User not found",
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: "Invalid username or password",
        });
      }
    }

    // =========================
    // VALIDATION
    // =========================
    if (!user) {
      return res.status(400).json({
        user: user,
        success: false,
        message: "Missing login data",
      });
    }

    // =========================
    // JWT TOKEN
    // =========================
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET as string,
      { expiresIn: "2h" },
    );

    return res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        token,
      },
    });
  } catch (error: any) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error?.message,
    });
  }
});
///////////////////////////////////////////////////
//dashboard
//////////////////////////////////////////////////
app.get("/dashboard", async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "No token",
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as {
      id: string;
    };

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});
/////////////////////////////////////////////////
//reveiw page
////////////////////////////////////////////////
app.post("/review", auth, async (req: Request, res: Response) => {
  try {
    const { code, language, filename } = req.body;

    if (!code || !language || !filename) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields",
      });
    }

    if (code.length > 20000) {
      return res.status(400).json({
        success: false,
        message: "Code is too long",
      });
    }

    const { text } = await generateText({
      model: "openai/gpt-4o-mini",
      prompt: `
You are a senior software engineer performing a code review.

Your job:
- Analyze the code carefully
- Detect bugs, bad practices, performance issues, security risks, and architecture problems
- Explain how to improve the code
- Give practical fixes
- Infer the feature purpose from the file name and code itself

Rules:
- Max 200 words
- Be direct and technical
- Do not rewrite the full file
- Focus only on important issues
- Mention exact problems
- Suggest clean solutions

Project context:
- File name: ${filename}
- Language: ${language}

Response format:

Title: <generate a short title based on the code purpose>

Issues:
1. <problem>
   Fix: <solution>

2. <problem>
   Fix: <solution>

3. <problem>
   Fix: <solution>

Quick Tips:
- <tip>
- <tip>

Code to review:
${code}
`,
    });

    return res.status(200).json({
      success: true,
      result: {
        text,
        filename,
        language,
        reviewedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

//////////////////////////////////////////////////
// server
app.listen(PORT, () => {
  console.log(`✅🏃‍♂️‍➡️Server running on port ${PORT}`);
});
