import * as authService from '../services/authService'
import * as authMiddleware from '../middleware/authMiddleware'
import express from 'express'
import type { role } from '@prisma/client'

const router = express.Router()

router.get('/me', authMiddleware.protect, async (req, res) => {
  const user = req.body.user
  res.status(200).json({
    status: 'success',
    user: {
      id: user.id,
      username: user.organizer?.name || 'unknown',
      events: user.organizer?.events || [],
      roles: user.roles.map((role: role) => role.name),
    },
  })
})

router.post('/authenticate', async (req, res) => {
  const { username, password } = req.body
  // Ensure `findByUsername` returns a user or null
  const user = await authService.findByUsername(username)
  if (!user) {
    res.status(401).json({ message: "User doesn't exist" })
    return
  }

  if (!password || !user.password) {
    res.status(400).json({ message: 'Password is required' })
    return
  }

  const isPasswordCorrect = await authService.comparePassword(
    password,
    user.password
  )
  if (!isPasswordCorrect) {
    res.status(401).json({ message: 'Invalid credentials' })
    return
  }

  const token = authService.generatetoken(user.id)
  res.status(200).json({
    status: 'success',
    access_token: token,
    user: {
      id: user.id,
      username: user.organizer?.name || 'unknown',
      roles: user.roles.map((role: role) => role.name),
    },
  })
  return
})

router.post(
  '/admin',
  authMiddleware.protect,
  authMiddleware.checkAdmin,
  async (req, res) => {
    res.status(200).json({
      status: 'success',
      message: 'You are an admin',
    })
  }
)

export default router
