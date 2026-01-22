import { Body, Controller, Get, Post, Param } from '@nestjs/common';
import { OrganizationsService } from './organizations.service';
import { CreateOrganizationDto } from './dtos/create-organization.dto';
import { InviteMemberDto } from './dtos/invite-member.dto';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../modules/auth/interfaces/authenticated-user.interface';
import { UseGuards } from '@nestjs/common';
import { OrgMemberGuard } from './guards/org-member.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { RequirePermissions } from './decorators/require-permissions.decorator';

@Controller('orgs')
export class OrganizationsController {
    constructor(private readonly orgsService: OrganizationsService) { }

    @Post()
    create(@CurrentUser() user: AuthenticatedUser, @Body() dto: CreateOrganizationDto) {
        return this.orgsService.create(user.id, dto);
    }

    @Get()
    findAll(@CurrentUser() user: AuthenticatedUser) {
        return this.orgsService.findAllForUser(user.id);
    }
    @Post(':orgId/invites')
    @UseGuards(OrgMemberGuard, PermissionsGuard)
    @RequirePermissions('invite')
    invite(
        @CurrentUser() user: AuthenticatedUser,
        @Param('orgId') orgId: string,
        @Body() dto: InviteMemberDto
    ) {
        return this.orgsService.inviteMember(user.id, orgId, dto);
    }

    @Post('invites/:token/accept')
    accept(
        @CurrentUser() user: AuthenticatedUser,
        @Param('token') token: string
    ) {
        return this.orgsService.acceptInvite(user.id, token);
    }
}
