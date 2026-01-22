import { IsEmail, IsNotEmpty, IsUUID } from 'class-validator';

export class InviteMemberDto {
    @IsEmail()
    @IsNotEmpty()
    email!: string;

    @IsNotEmpty()
    roleName: string = 'MEMBER'; // Default role
}
