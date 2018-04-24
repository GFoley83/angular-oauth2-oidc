import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Injectable, Optional } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import { catchError } from 'rxjs/operators';

import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthService } from '../oauth-service';
import { OAuthStorage } from '../types';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';

@Injectable()
export class DefaultOAuthInterceptor implements HttpInterceptor {
    private authStorage: OAuthStorage;

    constructor(
        private authService: OAuthService,
        private errorHandler: OAuthResourceServerErrorHandler,
        @Optional() private moduleConfig: OAuthModuleConfig
    ) {
        this.authStorage = authService.getStorage();
    }

    private checkUrl(url: string): boolean {
        let found = this.moduleConfig.resourceServer.allowedUrls.find(u => url.startsWith(u));
        return !!found;
    }

    public intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

        let url = req.url.toLowerCase();

        if (!this.moduleConfig) return next.handle(req);
        if (!this.moduleConfig.resourceServer) return next.handle(req);
        if (!this.moduleConfig.resourceServer.allowedUrls) return next.handle(req);
        if (!this.checkUrl(url)) return next.handle(req);

        let sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;

        if (sendAccessToken) {

            let token = this.authStorage.getItem('access_token');
            let header = 'Bearer ' + token;

            let headers = req.headers
                .set('Authorization', header);

            req = req.clone({ headers });
        }

        return next.handle(req).pipe(
            catchError(err => this.errorHandler.handleError(err))
        );

    }

}