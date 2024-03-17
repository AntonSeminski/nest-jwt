import {createParamDecorator} from '@nestjs/common';
import {AuthInfo, RequestUserInfo} from '../services';
import {EAuthInfo} from "../types";

export const AccessTokenInfo = createParamDecorator(
    async (data: EAuthInfo, context) => {
        const request = context.switchToHttp().getRequest();

        return RequestUserInfo.getByName(request, data) ?? await AuthInfo.getByName(request, data);
    })