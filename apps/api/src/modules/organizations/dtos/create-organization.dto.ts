import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class CreateOrganizationDto {
    @IsNotEmpty()
    @IsString()
    @MinLength(3)
    name!: string;

    @IsNotEmpty()
    @IsString()
    @MinLength(3)
    @Matches(/^[a-z0-9-]+$/, {
        message: 'Slug can only contain lowercase letters, numbers, and hyphens',
    })
    slug!: string;
}
