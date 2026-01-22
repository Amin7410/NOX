import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { prisma } from '@nox/database';

@Injectable()
export class OrgMemberGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const user = request.user;
        const orgId = request.params.orgId || request.body.orgId;

        if (!user || !orgId) {
            return false; // Should be handled by global auth guard, but safe check
        }

        const membership = await prisma.orgMember.findUnique({
            where: {
                orgId_userId: {
                    orgId,
                    userId: user.id,
                },
            },
            include: { role: true },
        });

        if (!membership) {
            throw new ForbiddenException('You are not a member of this organization');
        }

        // Attach membership/role to request for next guards/controller
        request.orgMember = membership;
        return true;
    }
}
