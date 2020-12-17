const request = require("supertest")

const server = require("./server")
const db = require('../data/dbConfig')
const Users = require('../api/auth/auth-users-modal')

describe("POST", () => {
    beforeAll(async () => {
        await db("users").truncate()
    })

    it("add a new user", async () => {
        await Users.add({ username: "user1", password: "abc123" })
        await Users.add({ username: "user2", password: "abc123" })
        const user = await db("users")

        expect(user).toHaveLength(2)
        expect(user[1].username).toBe("user2")
    })
    
    it("login", () => {
        return request(server)
            .post("/api/auth/login")
            .send({ username: "goose", password: "abc123" })
            .then(res => {
                expect(res.type).toMatch(/json/i)
            })
    })

    it("returns json from the jokes router", () => {
        return request(server)
        .get("/api/jokes")
        .then(res => {
            expect(res.type).toMatch(/json/i)
        })
    })
})

describe("GET /jokes", () => {
    it("should return 500 error", async () => {
        await request(server)
            .get("/api/jokes")
            .then(res => expect(res.status).toBe(500))
            .catch(err => console.log(err))
    })
})