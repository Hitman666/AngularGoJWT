import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';

import { AppComponent } from './app.component';
import { HomeComponent } from './home/home.component';
import { LoginComponent } from './login/login.component';
import { MembersComponent } from './members/members.component';

import { AuthService } from './auth.service';
import { AuthInterceptorService } from './auth-interceptor.service';
import { CanActivateViaAuthGuard } from './can-activate-via-auth.guard';

const routes = [
    { path: 'login', component: LoginComponent },
    {
        path: 'members',
        component: MembersComponent,
        canActivate: [
            CanActivateViaAuthGuard
        ]
    },
    { path: '', component: HomeComponent },
    { path: '**', redirectTo: '' }
];

@NgModule({
    declarations: [
        AppComponent,
        HomeComponent,
        LoginComponent,
        MembersComponent
    ],
    imports: [
        BrowserModule,
        FormsModule,
        ReactiveFormsModule,
        HttpClientModule,
        RouterModule.forRoot(routes)
    ],
    providers: [
        AuthService,
        {
            provide: HTTP_INTERCEPTORS,
            useClass: AuthInterceptorService,
            multi: true
        },
        CanActivateViaAuthGuard
    ],
    bootstrap: [AppComponent]
})
export class AppModule { }
