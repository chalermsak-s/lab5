import { AuthResponse } from '../models/authResponse'
import type { RegisterRequest } from '../models/registerRequest'
import * as authRepo from '../repository/authRepository'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { PrismaClient } from '@prisma/client'

export function findByUsername(username: string) {
  return authRepo.findByUsername(username)
}

export async function getUserFromToken(token: string) {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined')
  }
  const decoded = jwt.verify(token, process.env.JWT_SECRET) as jwt.JwtPayload
  return await authRepo.findByUserId(decoded.userId)
}
export function comparePassword(password: string, hash: string) {
  return bcrypt.compare(password, hash)
}

export function generatetoken(userId: number) {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined')
  }
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '5h' })
}

export function registerUser(registerRequest: RegisterRequest) {
  const { organizerName, username, password } = registerRequest
  return authRepo.registerUser(
    organizerName,
    username,
    bcrypt.hashSync(password),
    ['ROLE_USER']
  )
}

export function updatePassword(userId: number, password: string) {
  return authRepo.updatePassword(userId, bcrypt.hashSync(password))
}
