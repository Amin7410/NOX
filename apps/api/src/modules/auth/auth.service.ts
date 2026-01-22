import { Injectable, UnauthorizedException, BadRequestException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { prisma } from '@nox/database';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';

@Injectable()
export class AuthService {
    constructor(private jwtService: JwtService) { }

    async register(dto: RegisterDto): Promise<any> {
        try {
            console.log('[AUTH] Starting registration for:', dto.email);

            // 1. Check if user exists
            console.log('[AUTH] Checking if user exists...');
            const existingUser = await prisma.user.findUnique({
                where: { email: dto.email },
            });

            if (existingUser) {
                throw new ConflictException('Email already in use');
            }

            // 2. Hash password
            console.log('[AUTH] Hashing password...');
            const salt = await bcrypt.genSalt(10);
            const passwordHash = await bcrypt.hash(dto.password, salt);

            // 3. Create User in Transaction (User + UserSecurity)
            console.log('[AUTH] Creating user in database...');
            const user = await prisma.$transaction(async (tx) => {
                const newUser = await tx.user.create({
                    data: {
                        email: dto.email,
                        fullName: dto.fullName,
                        status: 'ACTIVE', // TODO: Email verification later
                    },
                });

                await tx.userSecurity.create({
                    data: {
                        userId: newUser.id,
                        passwordHash,
                        isPasswordSet: true,
                    },
                });

                return newUser;
            });

            console.log('[AUTH] User created successfully:', user.id);

            // 4. Generate Token
            return this.generateTokens(user.id, user.email);
        } catch (error) {
            console.error('[AUTH] Registration error:', error);
            console.error('[AUTH] Error stack:', (error as Error).stack);
            throw error;
        }
    }

    async login(dto: LoginDto): Promise<any> {
        const user = await prisma.user.findUnique({
            where: { email: dto.email },
            include: { security: true },
        });

        if (!user || !user.security?.passwordHash) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const isMatch = await bcrypt.compare(dto.password, user.security.passwordHash);
        if (!isMatch) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Generate token and return with user data
        const payload = { sub: user.id, email: user.email };
        return {
            accessToken: this.jwtService.sign(payload),
            user: {
                id: user.id,
                email: user.email,
                fullName: user.fullName,
                avatarUrl: user.avatarUrl,
            },
        };
    }

    private generateTokens(userId: string, email: string) {
        const payload = { sub: userId, email };
        return {
            accessToken: this.jwtService.sign(payload),
            user: {
                id: userId,
                email: email,
            },
        };
    }
}
