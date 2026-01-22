import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { prisma } from '@nox/database';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_SECRET || 'super-secret-key-change-me',
        });
    }

    async validate(payload: any) {
        // This payload comes from the decoded JWT
        const user = await prisma.user.findUnique({
            where: { id: payload.sub },
            select: { id: true, email: true, status: true },
        });

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        if (user.status === 'BANNED' || user.status === 'DELETED') {
            throw new UnauthorizedException('User account is not active');
        }

        // This object is injected into request.user
        return user;
    }
}
