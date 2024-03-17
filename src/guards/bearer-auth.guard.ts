import {AuthGuard} from "./auth.guard";
import {WorkspaceTokenService} from "../workspace-token.service";

export class BearerAuthGuard extends AuthGuard(WorkspaceTokenService) {}