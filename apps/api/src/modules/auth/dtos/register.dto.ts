import { IsEmail, IsNotEmpty, MinLength, MaxLength } from 'class-validator';

export class RegisterDto {
    @IsEmail({}, { message: 'Invalid email address' })
    @IsNotEmpty()
    email!: string;

    @IsNotEmpty()
    @MinLength(6, { message: 'Password must be at least 6 characters' })
    @MaxLength(32, { message: 'Password must not exceed 32 characters' })
    password!: string;

    @IsNotEmpty()
    @MinLength(2)
    fullName!: string;
}
