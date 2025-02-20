const express = require(`express`);
const cors = require(`cors`)
const { PrismaClient } = require(`@prisma/client`)
const jwt = require(`jsonwebtoken`);
const bcrypt = require(`bcrypt`);

const app = express();
const prisma = new PrismaClient();
const PORT = 3000;
app.use(cors());
app.use(express.json());

app.get(`/`, (req, res) => {
    res.send(`Merhaba, Ekşi Sunucuya hoşgeldiniz! `)
});

app.post(`/auth/signup`, async (req, res) => {
    const { firstName, lastName, username, email, password, verifyPassword } = req.body;

    try {
        if (!firstName || !lastName || !username || !email || !password || !verifyPassword) {
            return res.status(400).json({
                status: "error",
                comment: "Invalid data"
            })
        }

        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [{ email }, { username }]
            }
        })

        if (existingUser) {
            return res.status(400).json({
                status: "error",
                comment: "This user already exist"
            })
        }

        if (password !== verifyPassword) {
            return res.status(400).json({
                status: "error",
                comment: "Passwords do not match. Please try again."
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await prisma.user.create({
            data: {
                firstName: firstName,
                lastName: lastName,
                username: username,
                email: email,
                hashedPassword: hashedPassword
            }
        })

        res.status(200).json({
            status: "success",
            comment: `User created`
        })
    } catch (error) {
        console.log(error.message);
        res.status(500).json({
            status: "error",
            comment: "An unexpected error occurred. Please try again later."
        })
    }
})

app.post(`/auth/login`, async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({
                status: "error",
                comment: "Email and password are required"
            });
        }

        const existUser = await prisma.user.findUnique({
            where: { email: email }
        })

        if (!existUser) {
            return res.status(404).json({
                status: "error",
                comment: "This user does not exist"
            })
        }

        const comparePassword = await bcrypt.compare(password, existUser.hashedPassword);

        if (!comparePassword) {
            return res.status(400).json({
                status: "error",
                comment: "Wrong password"
            })
        }

        const token = jwt.sign({ userId: existUser.id }, `secret`, { expiresIn: "1h" });

        res.status(200).json({
            status: `success`,
            comment: `Login succesful`,
            token: token
        })
    } catch (error) {
        console.log(error.message);
        res.status(500).json({
            status: `error`,
            comment: `An unexpected error occurred. Please try again later.`
        })
    }
})

const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"]?.replace("Bearer ", "").trim();
    if (!token) {
        return res.status(400).json({
            status: `error`,
            comment: `Access denied. No token provided.`
        })
    }

    jwt.verify(token, `secret`, (err, decoded) => {
        console.log(decoded);
        if (err) {
            console.log(err.message);
            return res.status(401).json({
                status: `error`,
                comment: `Invalid token.`
            })
        }
        console.log(decoded);
        req.user = decoded;
        next();
    })
}

app.patch(`/auth/change-password`, authenticateToken, async (req, res) => {
    const { oldPassword, newPassword, verifyPassword } = req.body;

    try {
        if (!oldPassword || !newPassword || !verifyPassword) {
            return res.status(400).json({
                status: `error`,
                comment: `Missing information`
            })
        }

        if (newPassword !== verifyPassword) {
            return res.status(400).json({
                status: `error`,
                comment: `Make sure you put the right infos`
            })
        }

        const userId = req.user.userId;

        const user = await prisma.user.findUnique({
            where: { id: userId }
        })
        const isSamePassword = await bcrypt.compare(user.hashedPassword, newPassword);

        if (isSamePassword) {
            return res.status(400).json({
                status: `error`,
                comment: `Invalid info`
            })
        }
        const isPasswordMatch = await bcrypt.compare(oldPassword, user.hashedPassword);

        if (!isPasswordMatch) {
            return res.status(400).json({
                status: `error`,
                comment: `Invalid info`
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await prisma.user.update({
            where: { id: userId },
            data: {
                hashedPassword: hashedPassword
            }
        })

        res.status(200).json({
            status: `success`,
            comment: `password changed`
        })

    } catch (error) {
        console.log(error.message);
        res.status(500).json({
            status: `error`,
            comment: `Something went wrong: ${error.message}`
        })
    }
})

app.post(`/posts`, authenticateToken, async (req, res) => {

    const { title, description } = req.body;
    try {
        if (!title || !description) {
            return res.status(400).json({
                status: `error`,
                comment: `Invalid info`
            })
        }

        const existPost = await prisma.post.findUnique({
            where: { title: title }
        })

        if (existPost) {
            return res.status(400).json({
                status: `error`,
                comment: `This post already exist`
            })
        }

        const userId = req.user.userId;

        const newPost = await prisma.post.create({
            data: {
                title: title,
                description: description,
                userId: userId
            }
        })

        return res.status(201).json({
            status: `success`,
            comment: `Post created successfully`,
            post: newPost
        });

    } catch (error) {
        console.log(error.message);
        res.status(500).json({
            status: `error`,
            comment: `Something went wrong ${error.message}`
        })
    }
})

app.patch(`/change_post`, authenticateToken, async (req, res) => {
    const { title, newDescription } = req.body;
    try {
        if (!title || !newDescription) {
            return res.status(400).json({
                status: `error`,
                comment: `Missing info`
            })
        }

        const existPost = await prisma.post.findUnique({
            where: { title: title }
        })

        if (!existPost) {
            return res.status(404).json({
                status: `error`,
                comment: `This post does not exist`
            })
        }

        const updatedPost = await prisma.post.update({
            where: { title: title },
            data: {
                description: newDescription
            }
        })

        res.status(200).json({
            status: `success`,
            comment: `Post updated`,
            post: updatedPost
        })
    } catch (error) {
        console.log(error);
        res.status(500).json({
            status: `error`,
            comment: `Something went wrong ${error.message}`,
        })
    }
})

app.delete(`/delete_post`, authenticateToken, async (req, res) => {
    const { title } = req.body;
    try {
        if (!title) {
            return res.status(400).json({
                status: `error`,
                comment: `Invalid info`
            })
        }

        const existPost = await prisma.post.findUnique({
            where: { title: title }
        })

        if (!existPost) {
            return res.status(404).json({
                status: `error`,
                comment: `This post does not exist`
            })
        }

        await prisma.post.delete({
            where: { title: title }
        })

        res.status(200).json({
            status: `success`,
            comment: `${title} named post is deleted`
        })
    } catch (error) {
        console.log(error.message);
        res.status(500).json({
            status: `error`,
            comment: `Something went wrong. Please try again later.`
        })
    }
})

app.get(`/posts`, authenticateToken, async (req, res) => {
    try {
        if (!req.user || !req.user.userId) {
            return res.status(401).json({
                status: "error",
                comment: "Unauthorized: No user ID found."
            });
        }

        const userId = req.user.userId;

        const existingPosts = await prisma.post.findMany({
            where: { userId: userId }
        });

        if (!existingPosts || existingPosts.length === 0) {
            return res.status(404).json({
                status: "error",
                comment: "No posts found for this user."
            });
        }

        res.status(200).json({
            status: "success",
            comment: `There are ${existingPosts.length} posts for user ${userId}.`,
            posts: existingPosts
        });

    } catch (error) {
        console.error("Error fetching posts:", error);
        res.status(500).json({
            status: "error",
            comment: `Something went wrong: ${error.message}`
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`)
});