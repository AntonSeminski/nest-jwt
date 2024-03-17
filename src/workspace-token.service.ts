import {Inject, Injectable} from '@nestjs/common';
import {JwtTokenService} from "./jwt-token.service";

@Injectable()
export class WorkspaceTokenService extends JwtTokenService
{
    constructor(
        @Inject('SECRET') secret: string,
        @Inject('EXPIRES') expires: string
    ) {
        super(secret, expires);
    }
}
