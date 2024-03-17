import {DynamicModule} from "@nestjs/common";
import {JwtModule} from "@nestjs/jwt";
import {WorkspaceTokenService} from "./workspace-token.service";

export class JwtAuthModule {
    static register(options: {
        secret: string
        expires: string
    }): DynamicModule {
        return {
            module: JwtAuthModule,
            global: true,

            imports: [JwtModule.register({secret: options.secret})],
            providers: [
                {
                    provide: "SECRET",
                    useValue: options.secret
                },
                {
                    provide: "EXPIRES",
                    useValue: options.expires
                },
                WorkspaceTokenService
            ],
            exports: [WorkspaceTokenService]
        };
    }

}