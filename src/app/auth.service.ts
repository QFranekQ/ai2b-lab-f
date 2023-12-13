import {Injectable} from '@angular/core';
import {JwtHelperService} from "@auth0/angular-jwt";
import {AuthToken} from "./auth-token";
import {Observable, tap} from "rxjs";
import {AuthResponse} from "./auth-response";
import {HttpClient} from "@angular/common/http";

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor(
    private jwtHelper: JwtHelperService,
    private http: HttpClient,

  ) { }

  public isAuthenticated(): boolean {
    return !this.jwtHelper.isTokenExpired();
  }
  public isAdmin(): boolean {
    const token = this.jwtHelper.decodeToken() as AuthToken;
    console.log(token)
    if (!this.isAuthenticated()) {
      return false;
    }
    return token && token.roles && token.roles.includes('ADMIN');
  }
  public login(username: String, password: String): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>('https://labjwt.zecer.wi.zut.edu.pl/api/auth/login', {username, password})
      .pipe(tap(response => {
          if (response.token) {
            localStorage.setItem('access_token', response.token);
          } else {
            localStorage.removeItem('access_token');
          }
        })
      )
      ;
  }
  public getUsername(): string | null {
    const token = this.jwtHelper.decodeToken() as AuthToken;
    return token?.sub;
  }
  public logout(): void {
    localStorage.removeItem('access_token');
  }
}
