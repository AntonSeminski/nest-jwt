import {CanActivate, ExecutionContext, Inject, Injectable, mixin} from '@nestjs/common';
import {throwException} from "@buildery/nest-exception-handling";
import {CODES} from "@buildery/error-codes";
import {JwtTokenService} from "../jwt-token.service";

export const AuthGuard: any = (tokenServiceType: JwtTokenService) => {
    @Injectable()
    class Auth implements CanActivate {
        constructor(@Inject(tokenServiceType) private tokenService) {}

        async canActivate(context: ExecutionContext,): Promise<boolean> {
            const request = context.switchToHttp().getRequest();

            try {
                let accessToken: string = undefined;

                //is internal
                if (request.headers?.isinternal) {
                    request.user = {
                        userId: request.headers?.['internal-user-id'],
                        domain: request.headers?.['internal-domain']
                    }

                    console.log(`set internal user id: ${JSON.stringify(request.user)}`);

                    return true;
                }

                // check cookies
                const [domain, app, base] = request.headers?.['origin']
                    ?.substring(`http://`.length) //skip http://
                    ?.split('.') ?? [];

                if (domain) {
                    accessToken = request.cookies?.[`${domain}.${'accessToken'}`];
                }

                // check authorization header
                if (!accessToken && request.headers.authorization) {
                    const [type, token] = request.headers.authorization?.split(' ') ?? [];

                    if (type !== 'Bearer') throwException(CODES.USER.NOT_LOGGED_IN);

                    accessToken = token;
                }

                if (!accessToken) throwException(CODES.USER.NOT_LOGGED_IN);

                request.headers.authorization = `Bearer ${accessToken}`;
                request.user = await this.tokenService.verify(accessToken);

                console.log(`set authorization header user id: ${JSON.stringify(request.user)}`);

                return true;
            } catch (e) {
                console.log(`e: ${e.message}`)
                if (e.message.includes('expired')) throwException(CODES.SESSION.EXPIRED);
                if (e.message.includes('signature')) throwException(CODES.AUTH.WRONG_CREDENTIALS);

                return false;
            }
        }
    }

    return mixin(Auth);
}
