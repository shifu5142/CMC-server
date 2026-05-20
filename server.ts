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

    company: {
      type: String,
      default: "",
      trim: true,
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
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
You are an expert senior software engineer performing a professional code review.

You MUST follow the instructions exactly. Do NOT add any extra text outside the required JSON.

---

## OUTPUT REQUIREMENT (VERY IMPORTANT)

Return ONLY valid JSON.

No markdown.
No explanations outside JSON.
No backticks.
No comments.
No extra keys.

---

## JSON FORMAT (STRICT)

You must return exactly this structure:

{
  "description": string,
  "fixedCode": string,
  "security": number,
  "performance": number,
  "maintainability": number,
  "score": number
}

---

## FIELD RULES

### 1. description
- Must be MAX 200 words
- Must explain:
  - 🐞 Bugs and logic errors
  - ⚠️ Bad practices and anti-patterns
  - 🚀 Performance issues and optimization opportunities
  - 🔒 Security vulnerabilities and risks
  - 🧩 Maintainability and readability problems
  - ✅ Clear and practical fixes
- Must be technical and direct
- No greetings
- No filler text
- Focus only on actionable engineering feedback

---

### 2. fixedCode
- Must contain ONLY corrected code
- No explanations inside the code
- No markdown formatting
- If multiple fixes exist, return full corrected version of the file
- If no changes are needed, return the original code unchanged

---

### 3. security
- Integer from 1 to 100
- Grade security quality of the code
- 1 = critical vulnerabilities
- 100 = enterprise-grade security

---

### 4. performance
- Integer from 1 to 100
- Grade runtime and optimization quality
- 1 = extremely inefficient
- 100 = highly optimized

---

### 5. maintainability
- Integer from 1 to 100
- Grade readability, architecture, scalability, and code quality
- 1 = impossible to maintain
- 100 = extremely maintainable

---

### 6. score
- Integer from 1 to 100
- Overall code quality score
- Must reflect combined quality of:
  - security
  - performance
  - maintainability
  - bug severity
  - architecture quality
  - best practices

---

## IMPORTANT RULES (CRITICAL)

- You MUST output valid JSON only
- You MUST NOT include any text before or after JSON
- You MUST NOT wrap output in markdown
- You MUST ensure JSON is parseable by JSON.parse()
- Escape all special characters properly

---

## CONTEXT

File name: ${filename}
Language: ${language}

---

## CODE TO REVIEW

${code}
`,
    });

    const parsed = JSON.parse(text) as {
      description: string;
      fixedCode: string;
      security: number;
      performance: number;
      maintainability: number;
      score: number;
    };

    return res.status(200).json({
      success: true,
      result: {
        description: parsed.description,
        code: parsed.fixedCode,
        security: parsed.security,
        performance: parsed.performance,
        maintainability: parsed.maintainability,
        score: parsed.score,
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
/////////////////////////////////////////////////
//setting
/////////////////////////////////////////////////
app.get("/settings", auth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.id;

    const user = await User.findById(userId).select("name email company role");

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      user: {
        name: user.name,
        email: user.email,
        company: user.company || "",
        role: user.role || "user",
      },
    });
  } catch (error: any) {
    console.error("SETTINGS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error?.message,
    });
  }
});
app.put("/settings", auth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.id;

    const { name, email, company, role } = req.body;

    if (!name || !email) {
      return res.status(400).json({
        success: false,
        message: "Name and email are required",
      });
    }

    const existingEmail = await User.findOne({
      email,
      _id: { $ne: userId },
    });

    if (existingEmail) {
      return res.status(400).json({
        success: false,
        message: "Email already in use",
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        name: name.trim(),
        email: email.trim().toLowerCase(),
        company: company?.trim() || "",
        role: role === "admin" ? "admin" : "user",
      },
      {
        new: true,
        runValidators: true,
      },
    ).select("name email company role");

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (error: any) {
    console.error("UPDATE SETTINGS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error?.message,
    });
  }
});
//////////////////////////////////////////////////
// server
app.listen(PORT, () => {
  console.log(`✅🏃‍♂️‍➡️Server running on port ${PORT}`);
});
