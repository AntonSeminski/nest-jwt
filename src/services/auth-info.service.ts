import {JwtService} from '@nestjs/jwt';
import {CODES} from '@buildery/error-codes';
import {isHasEmpty} from '@buildery/nestjs-utils';
import {throwException} from "@buildery/nest-exception-handling";
import {EAuthInfo, IAuthInfo} from "../types";
import {JwtTokenService} from "../jwt-token.service";

/**
 * @description Service to handle Authorization header info
 * ***/
export class AuthInfo {
    public static async validate (request, authType, jwtService: JwtTokenService): Promise<IAuthInfo> {
        if (isHasEmpty(request, authType, jwtService)) throwException(CODES.AUTH.NO_AUTH_HEADER);

        const authHeader = request.headers?.authorization;
        if (!authHeader) throwException(CODES.AUTH.NO_AUTH_HEADER);

        const [type, token] = authHeader.split(' ');

        if (type !== authType) throwException(CODES.AUTH.WRONG_AUTH_TYPE);

        if (!token) throwException(CODES.AUTH.NO_TOKEN);

        const payload = await jwtService
            .verify(token)
            .catch(error => throwException( CODES.AUTH.WRONG_CREDENTIALS, {reason: error.message} ));

        if (!payload) throwException(CODES.AUTH.NO_TOKEN_PAYLOAD);

        return payload;
    }

    public static async getAll(request): Promise<IAuthInfo> {
        if (!request) throwException(CODES.COMMON.EMPTY_PARAM, { method: 'getAll' });

        const authHeader = request.headers.authorization;
        if (!authHeader) throwException(CODES.AUTH.NO_AUTH_HEADER);

        const token = authHeader.split(' ')?.[1];
        if (!token) throwException(CODES.AUTH.NO_TOKEN);

        return new JwtService({}).decode(token);
    }

    public static async getByName (request, fieldName: EAuthInfo) {
        return (await this.getAll(request))[fieldName];
    }

    public static async getByNames (request, fieldNames: Array<EAuthInfo>): Promise<Array<any>> {
        const authPayload = await this.getAll(request.headers.authorization);

        return fieldNames.map(fieldName => authPayload[fieldName]);
    }
    
    public static async getUserId(request): Promise<string> {
        return this.getByName(request, EAuthInfo.userId);
    }
    
    public static async getDomain(request): Promise<string> {
        return this.getByName(request, EAuthInfo.domain);
    }
}