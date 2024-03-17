import {EAuthInfo, IAuthInfo} from "../types";

export class RequestUserInfo {
    public static async getAll(request): Promise<IAuthInfo> {
        if (!request) return null;

        return request.user;
    }

    public static getByName (request, fieldName: EAuthInfo) {
        if (!request.user) return null;

        return request.user[fieldName];
    }

    public static getByNames (request, fieldNames: Array<EAuthInfo>): Array<string | any> {
        if (!request.user) return [];

        return fieldNames.map(fieldName => request.user[fieldName]);
    }

    public static getUserId(request): string {
        return this.getByName(request, EAuthInfo.userId);
    }

    public static getDomain(request): string {
        return this.getByName(request, EAuthInfo.domain);
    }
}
