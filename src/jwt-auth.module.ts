import {DynamicModule} from "@nestjs/common";
import {WorkspaceTokenService} from "./services";
import {JwtModule} from "@nestjs/jwt";

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