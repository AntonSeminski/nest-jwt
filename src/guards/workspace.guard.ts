import {AuthGuard} from "./auth.guard";
import {WorkspaceTokenService} from "../services";

export class WorkspaceGuard extends AuthGuard(WorkspaceTokenService) {}