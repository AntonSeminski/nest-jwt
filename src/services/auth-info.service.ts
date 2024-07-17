import {CODES} from '@buildery/error-codes';
import {isHasEmpty} from '@buildery/nestjs-utils';
import {throwException} from "@buildery/nest-exception-handling";
import {EAuthInfo, IAuthInfo} from "../types";
import {JwtTokenService} from "../jwt-token.service";
import {jwtDecode} from "jwt-decode";

/**
 * @description Service to handle Authorization header info
 * ***/
export class AuthInfo {
    public static async validate(request, authType, jwtService: JwtTokenService): Promise<IAuthInfo> {
        if (isHasEmpty(request, authType, jwtService)) throwException(CODES.AUTH.NO_AUTH_HEADER);

        const authHeader = request.headers?.authorization;
        if (!authHeader) throwException(CODES.AUTH.NO_AUTH_HEADER);

        const [type, token] = authHeader.split(' ');

        if (type !== authType) throwException(CODES.AUTH.WRONG_AUTH_TYPE);

        if (!token) throwException(CODES.AUTH.NO_TOKEN);

        const payload = await jwtService
            .verify(token)
            .catch(error => throwException(CODES.AUTH.WRONG_CREDENTIALS, { reason: error.message }));

        if (!payload) throwException(CODES.AUTH.NO_TOKEN_PAYLOAD);

        return payload;
    }

    public static getAll(request): IAuthInfo {
        if (!request || !request.headers) return null;

        const authHeader = request.headers.authorization;
        if (!authHeader) return null;

        const token = authHeader.split(' ')?.[1];
        if (!token) return null;

        return jwtDecode(token);
    }

    public static getByName(request, fieldName: EAuthInfo): any {
        return this.getAll(request)?.[fieldName];
    }

    public static getByNames(request, fieldNames: Array<EAuthInfo>): Array<any> {
        if (isHasEmpty(request, fieldNames)) return [];

        const authPayload = this.getAll(request.headers.authorization);

        return fieldNames.map(fieldName => authPayload[fieldName]);
    }

    public static getUserId(request): string {
        return this.getByName(request, EAuthInfo.userId);
    }

    public static getDomain(request): string {
        return this.getByName(request, EAuthInfo.domain);
    }
}