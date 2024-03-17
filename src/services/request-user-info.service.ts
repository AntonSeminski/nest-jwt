import {EAuthInfo, IAuthInfo} from "../types";

export class RequestUserInfo {
    public static async getAll(request: any): Promise<IAuthInfo> {
        if (!request) return null;

        return request.user;
    }

    public static getByName (request: any, fieldName: EAuthInfo) {
        if (!request.user) return null;

        return request.user[fieldName];
    }

    public static getByNames (request: any, fieldNames: Array<EAuthInfo>): Array<string | any> {
        if (!request.user) return [];

        return fieldNames.map(fieldName => request.user[fieldName]);
    }

    public static getUserId(request: any): string {
        return this.getByName(request, EAuthInfo.userId);
    }

    public static getUsername(request: any): string {
        return this.getByName(request, EAuthInfo.username);
    }

    public static getDomain(request: any): string {
        return this.getByName(request, EAuthInfo.domain);
    }
}
