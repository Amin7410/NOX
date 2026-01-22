import { Injectable, ConflictException } from '@nestjs/common';
import { prisma } from '@nox/database';
import { CreateOrganizationDto } from './dtos/create-organization.dto';
import { InviteMemberDto } from './dtos/invite-member.dto';

@Injectable()
export class OrganizationsService {
    async create(userId: string, dto: CreateOrganizationDto): Promise<any> {
        // 1. Check slug availability
        const existing = await prisma.organization.findUnique({
            where: { slug: dto.slug },
        });
        if (existing) {
            throw new ConflictException('Organization slug already exists');
        }

        // 2. Transaction: Create Org -> Create Owner Role -> Add Member
        return prisma.$transaction(async (tx) => {
            // a. Create Org
            const org = await tx.organization.create({
                data: {
                    name: dto.name,
                    slug: dto.slug,
                },
            });

            // b. Create Default Roles (OWNER at minimum)
            const ownerRole = await tx.role.create({
                data: {
                    orgId: org.id,
                    name: 'OWNER',
                    permissions: ['*'], // Full access
                },
            });

            // Also create ADMIN and MEMBER roles for future use
            await tx.role.createMany({
                data: [
                    { orgId: org.id, name: 'ADMIN', permissions: ['read', 'write', 'invite'] },
                    { orgId: org.id, name: 'MEMBER', permissions: ['read', 'write'] },
                    { orgId: org.id, name: 'VIEWER', permissions: ['read'] },
                ]
            });

            // c. Add Creator as Member with OWNER role
            await tx.orgMember.create({
                data: {
                    orgId: org.id,
                    userId: userId,
                    roleId: ownerRole.id,
                },
            });

            return org;
        });
    }

    async findAllForUser(userId: string): Promise<any> {
        return prisma.organization.findMany({
            where: {
                members: {
                    some: { userId },
                },
            },
            include: {
                members: {
                    where: { userId },
                    include: { role: true }
                }
            }
        });
    }

    async inviteMember(inviterId: string, orgId: string, dto: InviteMemberDto): Promise<any> {
        // 1. Check if user is already member
        const existingMember = await prisma.orgMember.findFirst({
            where: {
                orgId,
                user: { email: dto.email }
            }
        });

        if (existingMember) {
            throw new ConflictException('User is already a member of this organization');
        }

        // 2. Find Role
        const role = await prisma.role.findFirst({
            where: { orgId, name: dto.roleName }
        });

        if (!role) {
            throw new ConflictException(`Role ${dto.roleName} not found in this organization`);
        }

        // 3. Create Invitation
        const token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        return prisma.invitation.create({
            data: {
                email: dto.email,
                orgId,
                roleId: role.id,
                invitedById: inviterId,
                token,
                expiresAt,
                status: 'PENDING'
            }
        });
    }

    async acceptInvite(userId: string, token: string): Promise<any> {
        const invite = await prisma.invitation.findUnique({
            where: { token },
            include: { role: true }
        });

        if (!invite || invite.status !== 'PENDING' || invite.expiresAt < new Date()) {
            throw new ConflictException('Invalid or expired invitation');
        }

        return prisma.$transaction(async (tx) => {
            // 1. Create Member
            await tx.orgMember.create({
                data: {
                    orgId: invite.orgId,
                    userId,
                    roleId: invite.roleId,
                    invitedBy: invite.invitedById
                }
            });

            // 2. Update Invitation status
            return tx.invitation.update({
                where: { id: invite.id },
                data: {
                    status: 'ACCEPTED',
                    acceptedAt: new Date()
                }
            });
        });
    }
}
