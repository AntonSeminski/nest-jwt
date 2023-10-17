import {createParamDecorator} from '@nestjs/common';
import {AuthInfo} from '../services';

export const AccessTokenInfo = createParamDecorator(
    async (data: string, context) => {
        const request = context.switchToHttp().getRequest();

        return AuthInfo.getByName(request, data);
    })