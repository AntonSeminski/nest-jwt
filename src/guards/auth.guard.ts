import {CanActivate, ExecutionContext, Inject, Injectable, mixin} from '@nestjs/common';
import {JwtTokenService} from '../services';
import {throwException} from "@buildery/nestjs-utils";
import {CODES} from "@buildery/error-codes";

export const AuthGuard: any = (tokenServiceType: JwtTokenService) => {
    @Injectable()
    class Auth implements CanActivate {
        constructor(@Inject(tokenServiceType) private tokenService) {}

        async canActivate(context: ExecutionContext,): Promise<boolean> {
            const request = context.switchToHttp().getRequest();

            try {
                let accessToken: string;

                const [domain, app, base] = request.headers['origin']
                    ?.substring(`http://`.length) //skip http://
                    ?.split('.') ?? [];

                if (domain) {
                    accessToken = request.cookies[`${domain}.${'accessToken'}`];
                }

                if (!accessToken && request.headers.authorization) {
                    const [type, token] = request.headers.authorization?.split(' ') ?? [];

                    if (type !== 'Bearer') throwException(CODES.USER.NOT_LOGGED_IN);

                    accessToken = token;
                }

                if (!accessToken) throwException(CODES.USER.NOT_LOGGED_IN);

                request.headers.authorization = `Bearer ${accessToken}`;
                request.user = await this.tokenService.verify(accessToken);

                return true;
            } catch (e) {
                console.log(`e: ${e.message}`)
                if (e.message.includes('expired')) throwException(CODES.SESSION.EXPIRED);
                if (e.message.includes('signature')) throwException(CODES.AUTH.WRONG_CREDENTIALS);
            }
        }
    }

    return mixin(Auth);
}
