const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const port = process.env.PORT || 5000;
require('dotenv').config();

// Middleware
app.use(cors({
    origin: ['http://localhost:5173'],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());


const verifyToken = async (req, res, next) => {
    const cookiesToken = req.cookies?.token;
    const localStorageToken = req.headers?.authorization?.split(' ')[1];

    console.log('Headers: ', req.headers); // Debug to check headers

    // Check if token is present
    if (!cookiesToken && !localStorageToken) {
        return res.status(401).send({ error: true, message: 'Unauthorized access.' });
    }

    const tokenToVerify = cookiesToken && localStorageToken;

    jwt.verify(tokenToVerify, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            if (cookiesToken) {
                res.clearCookie('token');
                return res.status(401).send({ error: true, message: 'Unauthorized.' });
            }
            return res.status(401).send({ error: true, message: 'Unauthorized access.' });
        }

        req.decoded = decoded;
        next();
    });
};


const logger = async (req, res, next) => {
    next();
};

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xwnuc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        await client.connect();
        const usersCollection = client.db('nusrat').collection("users");
        const ProfileCollection = client.db('nusrat').collection("profile");
        const servicesCollection = client.db('nusrat').collection("services");
        const experienceCollection = client.db('nusrat').collection("experience");
        const portfolioCollection = client.db('nusrat').collection("portfolio");
        const SliderCollection = client.db('nusrat').collection("slider");
        const ReviewCollection = client.db('nusrat').collection("review");



        app.post('/jwt', async (req, res) => {
            const user = req.body;
            try {
                const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1h" });
                res.cookie('token', token, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'none',
                }).send({ success: true, token });
            } catch (error) {
                res.status(500).send({ success: false, message: 'Error generating token' });
            }
        });

        // app.post('/jwt', async (req, res) => {
        //     const user = req.body;
        //     try {
        //         const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1h" });

        //         res.cookie('token', token, {
        //             httpOnly: true,
        //             secure: process.env.NODE_ENV === 'production', // Use secure cookies only in production
        //             sameSite: 'none', // Needed for cross-origin requests if the frontend is on a different domain
        //         }).send({ success: true, token });
        //     } catch (error) {
        //         res.status(500).send({ success: false, message: 'Error generating token' });
        //     }
        // });



        // Verify Admin Middleware
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isAdmin = user?.role === 'admin';
            if (!isAdmin) {
                return res.status(403).send({ message: 'Forbidden access' });
            }
            next();
        };

        // Check if user is admin

        app.get('/users/admin/:email', verifyToken, async (req, res) => {
            const email = req.params.email;

            if (email !== req.decoded?.email) {
                return res.status(403).send({ message: 'Forbidden access' });
            }

            const query = { email: email };
            const user = await usersCollection.findOne(query);
            let admin = false;
            if (user) {
                admin = user?.role === 'admin';
            }
            res.send({ admin });
        });




        // Get all users (admin and moderator access)
        app.get('/users', logger, verifyToken, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        // Get a user by ID (admin and moderator access)
        app.get('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await usersCollection.findOne(query);
            res.send(result);
        });

        // Add a new user
        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);

            if (existingUser) {
                return res.send({ message: 'User already exists' });
            }

            const userWithRole = { ...user, role: 'user' };
            const result = await usersCollection.insertOne(userWithRole);
            res.send(result);
        });

        // Update user to admin
        app.patch('/users/admin/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const filter = { _id: new ObjectId(id) };
                const updatedDoc = {
                    $set: { role: 'admin' }
                };
                const result = await usersCollection.updateOne(filter, updatedDoc);
                res.send(result);
            } catch (error) {
                res.status(500).send({ error: 'Failed to update user role' });
            }
        });



        // Revert user role to 'user'
        app.patch('/users/revert/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const filter = { _id: new ObjectId(id) };
                const updatedDoc = {
                    $set: { role: 'user' }
                };
                const result = await usersCollection.updateOne(filter, updatedDoc);
                res.send(result);
            } catch (error) {
                res.status(500).send({ error: 'Failed to revert user role' });
            }
        });

        // Log out user
        app.post('/logout', async (req, res) => {
            res.clearCookie('token', { maxAge: 0 }).send({ success: true });
        });



        app.get('/getprofile', async (req, res) => {
            try {
                const result = await ProfileCollection.find().toArray();
                res.send(result);
            } catch (error) {
                res.status(500).send('Error fetching profile.');
            }
        });




        app.put('/updateprofile', async (req, res) => {
            const { imageUrl, id } = req.body;  // Expect the _id to be passed in the request body

            try {
                // Find the document by _id and update the imageUrl
                const updatedProfile = await ProfileCollection.updateOne(
                    { _id: new ObjectId(id) },  // Convert the id to ObjectId
                    { $set: { imageUrl } }
                );

                if (updatedProfile.modifiedCount === 1) {
                    res.status(200).send('Profile image updated successfully.');
                } else {
                    res.status(404).send('Profile not found or already up-to-date.');
                }
            } catch (error) {
                res.status(500).send('Error updating profile image.');
            }
        });


        app.post('/addexperience', verifyToken, verifyAdmin, async (req, res) => {
            const data = req.body;
            const result = await experienceCollection.insertOne(data);
            res.send(result);
        });

        app.get('/experience', async (req, res) => {
            const result = await experienceCollection.find().toArray()
            res.send(result)
        });

        app.delete('/deleteexperience/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }; // Ensure the ID is converted to ObjectId for MongoDB queries

            try {
                // Delete the portfolio document from MongoDB
                const result = await experienceCollection.deleteOne(query);

                if (result.deletedCount === 0) {
                    return res.status(404).send({ error: 'Portfolio not found' });
                }

                // Send success response
                res.send({ message: 'Portfolio deleted successfully', result });
            } catch (error) {
                console.error('Error deleting portfolio:', error);
                res.status(500).send({ error: 'Failed to delete portfolio' });
            }
        });


        // Services
        app.post('/addservice', verifyToken, verifyAdmin, async (req, res) => {
            const data = req.body;
            const result = await servicesCollection.insertOne(data);
            res.send(result);
        });

        app.get('/services', async (req, res) => {
            const result = await servicesCollection.find().toArray()
            res.send(result)
        });

        app.delete('/deleteservices/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }; // Ensure the ID is converted to ObjectId for MongoDB queries

            try {
                // Delete the portfolio document from MongoDB
                const result = await servicesCollection.deleteOne(query);

                if (result.deletedCount === 0) {
                    return res.status(404).send({ error: 'Portfolio not found' });
                }

                // Send success response
                res.send({ message: 'Portfolio deleted successfully', result });
            } catch (error) {
                console.error('Error deleting portfolio:', error);
                res.status(500).send({ error: 'Failed to delete portfolio' });
            }
        });



        app.post('/addportfolio', verifyToken, verifyAdmin, async (req, res) => {
            const data = req.body;
            const result = await portfolioCollection.insertOne(data);
            res.send(result);
        });

        app.get('/portfolio', async (req, res) => {
            const result = await portfolioCollection.find().toArray()
            res.send(result)
        })

        app.delete('/deleteportfolio/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }; // Ensure the ID is converted to ObjectId for MongoDB queries

            try {
                // Delete the portfolio document from MongoDB
                const result = await portfolioCollection.deleteOne(query);

                if (result.deletedCount === 0) {
                    return res.status(404).send({ error: 'Portfolio not found' });
                }

                // Send success response
                res.send({ message: 'Portfolio deleted successfully', result });
            } catch (error) {
                console.error('Error deleting portfolio:', error);
                res.status(500).send({ error: 'Failed to delete portfolio' });
            }
        });

        // sliders
        app.post('/addslider', verifyToken, verifyAdmin, async (req, res) => {
            const data = req.body;
            const result = await SliderCollection.insertOne(data);
            res.send(result);
        });

        app.get('/sliders', async (req, res) => {
            const result = await SliderCollection.find().toArray()
            res.send(result)
        })


        app.put('/updateslider/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { _id, ...updatedData } = req.body; // Exclude `_id` from the update data

            try {
                const result = await SliderCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updatedData }
                );

                if (result.modifiedCount === 0) {
                    return res.status(404).send({ error: 'Slider not found or no changes made' });
                }

                res.send({ message: 'Slider updated successfully', result });
            } catch (error) {
                console.error('Error updating slider:', error);
                res.status(500).send({ error: 'Failed to update slider' });
            }
        });






        app.delete('/deleteslider/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }; // Ensure the ID is converted to ObjectId for MongoDB queries

            try {
                // Delete the portfolio document from MongoDB
                const result = await SliderCollection.deleteOne(query);

                if (result.deletedCount === 0) {
                    return res.status(404).send({ error: 'Portfolio not found' });
                }

                // Send success response
                res.send({ message: 'Portfolio deleted successfully', result });
            } catch (error) {
                console.error('Error deleting portfolio:', error);
                res.status(500).send({ error: 'Failed to delete portfolio' });
            }
        });


        app.post('/addreview', verifyToken, verifyAdmin, async (req, res) => {
            const data = req.body;
            const result = await ReviewCollection.insertOne(data);
            res.send(result);
        });


        app.get('/reviews', async (req, res) => {
            const result = await ReviewCollection.find().toArray()
            res.send(result)
        })


        app.delete('/deletereview/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }; // Ensure the ID is converted to ObjectId for MongoDB queries

            try {
                // Delete the portfolio document from MongoDB
                const result = await ReviewCollection.deleteOne(query);

                if (result.deletedCount === 0) {
                    return res.status(404).send({ error: 'Portfolio not found' });
                }

                // Send success response
                res.send({ message: 'Portfolio deleted successfully', result });
            } catch (error) {
                console.error('Error deleting portfolio:', error);
                res.status(500).send({ error: 'Failed to delete portfolio' });
            }
        });


        // MongoDB Ping
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Upturn is ON');
});

app.listen(port, () => {
    console.log(`Upturn is on Port ${port}`);
});
