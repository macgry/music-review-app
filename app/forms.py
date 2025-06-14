from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange, URL, Optional

class RegisterForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Hasło', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Potwierdź hasło', validators=[DataRequired(), EqualTo('password', message='Hasła muszą być takie same')])
    submit = SubmitField('Zarejestruj się')

class LoginForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')

class ReviewForm(FlaskForm):
    rating = IntegerField('Ocena (1–5)', validators=[DataRequired(), NumberRange(min=1, max=5)])
    content = TextAreaField('Twoja recenzja', validators=[DataRequired()])
    submit = SubmitField('Dodaj recenzję')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Obecne hasło', validators=[DataRequired()])
    new_password = PasswordField('Nowe hasło', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField('Potwierdź nowe hasło', validators=[DataRequired(), EqualTo('new_password', message='Hasła muszą być takie same')])
    submit = SubmitField('Zmień hasło')

class CommentForm(FlaskForm):
    content = TextAreaField('Dodaj komentarz', validators=[DataRequired(), Length(min=1, max=500)])
    submit = SubmitField('Dodaj komentarz')

class AlbumProposalForm(FlaskForm):
    title = StringField('Tytuł albumu', validators=[DataRequired()])
    artist = StringField('Artysta', validators=[DataRequired()])
    genre = StringField('Gatunek')
    release_date = DateField('Data wydania', format='%Y-%m-%d')
    cover_url = StringField('URL okładki', validators=[URL(require_tld=True, message='Podaj poprawny adres URL')])
    submit = SubmitField('Zaproponuj album')
    spotify_url = StringField('Spotify URL', validators=[Optional(), URL()])
    youtube_url = StringField('YouTube URL', validators=[Optional(), URL()])