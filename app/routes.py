from flask import render_template, redirect, url_for, flash, request
from app import app, mysql
from app.forms import RegisterForm, LoginForm, ChangePasswordForm, CommentForm, AlbumProposalForm
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
@login_required
def home():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM albums")
    albums = cursor.fetchall()
    cursor.close()
    return render_template('home.html', albums=albums)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        hashed_password = generate_password_hash(password)

        cursor = mysql.connection.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, hashed_password))
            mysql.connection.commit()
            flash('Konto zostało utworzone pomyślnie!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Taka nazwa użytkownika już istnieje lub wystąpił błąd bazy danych!', 'danger')
            print(f"Błąd bazy danych: {e}")
        finally:
            cursor.close()

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        result = cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        data = cursor.fetchone()
        cursor.close()

        if data:
            # Tabela users ma kolumny: id, username, password_hash
            user = User(id=data[0], username=data[1], password=data[2])

            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Nieprawidłowe hasło!', 'danger')
        else:
            flash('Nie znaleziono użytkownika o podanej nazwie.', 'warning')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Wylogowano!', 'info')
    return redirect(url_for('login'))

from app.forms import ReviewForm

from app.forms import CommentForm

@app.route('/album/<int:album_id>', methods=['GET', 'POST'])
@login_required
def album_detail(album_id):
    cursor = mysql.connection.cursor()

    # Pobierz album
    cursor.execute("SELECT * FROM albums WHERE id = %s", (album_id,))
    album = cursor.fetchone()

    # Pobierz recenzje z info o autorze
    cursor.execute("""
        SELECT r.id, r.rating, r.content, r.created_at, u.username, u.id
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.album_id = %s
        ORDER BY r.created_at DESC
    """, (album_id,))
    reviews = cursor.fetchall()

    # Pobierz komentarze dla każdej recenzji
    comments_by_review = {}
    for review in reviews:
        review_id = review[0]
        cursor.execute("""
            SELECT c.content, c.created_at, u.username, u.id, c.id
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.review_id = %s
            ORDER BY c.created_at ASC
        """, (review_id,))
        comments_by_review[review_id] = cursor.fetchall()

    # Sprawdź, czy użytkownik polubił album
    cursor.execute("SELECT * FROM liked_albums WHERE user_id = %s AND album_id = %s", (current_user.id, album_id))
    album_liked = cursor.fetchone() is not None

    # Sprawdź, czy album jest dodany do 'do przesłuchania'
    cursor.execute("SELECT * FROM to_listen_albums WHERE user_id = %s AND album_id = %s", (current_user.id, album_id))
    album_in_listen_later = cursor.fetchone() is not None

    form = ReviewForm()

    # Rozdziel logikę dodawania recenzji i komentarzy
    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == 'comment':
            review_id = request.form.get('review_id')
            content = request.form.get('content')
            if review_id and content:
                cursor.execute("""
                    INSERT INTO comments (review_id, user_id, content)
                    VALUES (%s, %s, %s)
                """, (review_id, current_user.id, content))
                mysql.connection.commit()
                flash("Komentarz został dodany!", "success")
                return redirect(url_for('album_detail', album_id=album_id))

        elif form_type == 'review':
            print("FORMULARZ NIE PRZESZEDŁ WALIDACJI:", form.errors)
            if form.validate_on_submit():
                cursor.execute("""
                    INSERT INTO reviews (user_id, album_id, rating, content)
                    VALUES (%s, %s, %s, %s)
                """, (current_user.id, album_id, form.rating.data, form.content.data))
                mysql.connection.commit()
                flash("Recenzja została dodana!", "success")
                return redirect(url_for('album_detail', album_id=album_id))

    cursor.close()
    return render_template(
        'album_detail.html',
        album=album,
        reviews=reviews,
        comments_by_review=comments_by_review,
        form=form,
        album_liked=album_liked,
        album_in_listen_later=album_in_listen_later
    )

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    cursor = mysql.connection.cursor()

    # Nazwa użytkownika
    cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    # Recenzje użytkownika
    cursor.execute("""
        SELECT a.title, a.artist, r.rating, r.content, r.created_at
        FROM reviews r
        JOIN albums a ON r.album_id = a.id
        WHERE r.user_id = %s
        ORDER BY r.created_at DESC
    """, (user_id,))
    reviews = cursor.fetchall()

    # Polubione albumy
    cursor.execute("""
        SELECT a.id, a.title, a.artist, a.cover_url
        FROM albums a
        JOIN liked_albums l ON a.id = l.album_id
        WHERE l.user_id = %s
    """, (user_id,))
    liked_albums = cursor.fetchall()

    # Albumy "do przesłuchania"
    cursor.execute("""
        SELECT a.id, a.title, a.artist, a.cover_url
        FROM albums a
        JOIN to_listen_albums t ON a.id = t.album_id
        WHERE t.user_id = %s
    """, (user_id,))
    to_listen_albums = cursor.fetchall()

    cursor.close()

    return render_template(
        'profile.html',
        user=user,
        reviews=reviews,
        liked_albums=liked_albums,
        to_listen_albums=to_listen_albums
    )

@app.route('/review/<int:review_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_review(review_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id, album_id, rating, content FROM reviews WHERE id = %s", (review_id,))
    review = cursor.fetchone()

    if not review:
        flash("Nie znaleziono recenzji.", "warning")
        return redirect(url_for('home'))

    if review[0] != current_user.id:
        flash("Nie możesz edytować cudzej recenzji.", "danger")
        return redirect(url_for('home'))

    form = ReviewForm()
    if request.method == 'GET':
        form.rating.data = review[2]
        form.content.data = review[3]

    if form.validate_on_submit():
        cursor.execute("""
            UPDATE reviews
            SET rating = %s, content = %s
            WHERE id = %s
        """, (form.rating.data, form.content.data, review_id))
        mysql.connection.commit()
        flash("Recenzja została zaktualizowana.", "success")
        return redirect(url_for('album_detail', album_id=review[1]))

    cursor.close()
    return render_template('edit_review.html', form=form)

@app.route('/review/<int:review_id>/delete', methods=['POST'])
@login_required
def delete_review(review_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id, album_id FROM reviews WHERE id = %s", (review_id,))
    review = cursor.fetchone()

    if not review:
        flash("Nie znaleziono recenzji.", "warning")
        return redirect(url_for('home'))

    if review[0] != current_user.id and not current_user.is_admin:
        flash("Nie możesz usunąć cudzej recenzji.", "danger")
        return redirect(url_for('home'))

    cursor.execute("DELETE FROM reviews WHERE id = %s", (review_id,))
    mysql.connection.commit()
    flash("Recenzja została usunięta.", "info")
    return redirect(url_for('album_detail', album_id=review[1]))

# Wyświetlenie użytkowników i statusu znajomości
@app.route('/users')
@login_required
def users():
    cursor = mysql.connection.cursor()

    # Pobierz wszystkich użytkowników (oprócz siebie)
    cursor.execute("SELECT id, username FROM users WHERE id != %s", (current_user.id,))
    users = cursor.fetchall()

    # Pobierz relacje znajomych
    cursor.execute("SELECT sender_id, receiver_id, status FROM friends")
    relations = cursor.fetchall()
    relation_map = {}
    for sender_id, receiver_id, status in relations:
        relation_map[(sender_id, receiver_id)] = status

    # Pobierz ID znajomych zaakceptowanych
    friend_ids = []
    for (s_id, r_id), status in relation_map.items():
        if status == "accepted":
            if s_id == current_user.id:
                friend_ids.append(r_id)
            elif r_id == current_user.id:
                friend_ids.append(s_id)

    # Ostatnie recenzje znajomych
    recent_friend_reviews = []
    if friend_ids:
        cursor.execute("""
            SELECT r.album_id, a.title, r.rating, r.content, r.created_at, u.username
            FROM reviews r
            JOIN albums a ON r.album_id = a.id
            JOIN users u ON r.user_id = u.id
            WHERE r.user_id IN %s
            ORDER BY r.created_at DESC
            LIMIT 10
        """, (tuple(friend_ids),))
        rows = cursor.fetchall()
        for row in rows:
            recent_friend_reviews.append({
                "album_id": row[0],
                "album_title": row[1],
                "rating": row[2],
                "content": row[3],
                "created_at": row[4],
                "username": row[5]
            })

    # Aktywność znajomych (po polsku)
    friend_activity = []
    if friend_ids:
        # Polubienia
        cursor.execute("""
            SELECT u.username, a.title
            FROM liked_albums l
            JOIN users u ON l.user_id = u.id
            JOIN albums a ON l.album_id = a.id
            WHERE l.user_id IN %s
            ORDER BY a.title DESC
            LIMIT 10
        """, (tuple(friend_ids),))
        for username, album_title in cursor.fetchall():
            friend_activity.append(f"{username} polubił(a) album „{album_title}”")

        # Do przesłuchania
        cursor.execute("""
            SELECT u.username, a.title
            FROM to_listen_albums t
            JOIN users u ON t.user_id = u.id
            JOIN albums a ON t.album_id = a.id
            WHERE t.user_id IN %s
            ORDER BY a.title DESC
            LIMIT 10
        """, (tuple(friend_ids),))
        for username, album_title in cursor.fetchall():
            friend_activity.append(f"{username} dodał(a) album „{album_title}” do listy „Do przesłuchania”")

    # Wspólne polubione albumy
    shared_likes = []
    if friend_ids:
        for friend_id in friend_ids:
            cursor.execute("""
                SELECT a.id, a.title, u.username
                FROM liked_albums l1
                JOIN liked_albums l2 ON l1.album_id = l2.album_id
                JOIN albums a ON a.id = l1.album_id
                JOIN users u ON u.id = l2.user_id
                WHERE l1.user_id = %s AND l2.user_id = %s AND l1.user_id != l2.user_id
            """, (current_user.id, friend_id))
            for album_id, album_title, friend_username in cursor.fetchall():
                shared_likes.append({
                    "album_id": album_id,
                    "album_title": album_title,
                    "friend_username": friend_username
                })

    cursor.close()
    return render_template(
        'users.html',
        users=users,
        relation_map=relation_map,
        current_user_id=current_user.id,
        recent_friend_reviews=recent_friend_reviews,
        friend_activity=friend_activity,
        shared_likes=shared_likes
    )

# Wysyłanie zaproszenia
@app.route('/add_friend/<int:user_id>')
@login_required
def add_friend(user_id):
    cursor = mysql.connection.cursor()

    # Sprawdź, czy już istnieje relacja
    cursor.execute("""
        SELECT * FROM friends
        WHERE (sender_id = %s AND receiver_id = %s)
           OR (sender_id = %s AND receiver_id = %s)
    """, (current_user.id, user_id, user_id, current_user.id))
    if cursor.fetchone():
        flash("Zaproszenie zostało już wysłane lub jesteście już znajomymi.", "info")
    else:
        cursor.execute("""
            INSERT INTO friends (sender_id, receiver_id, status)
            VALUES (%s, %s, 'pending')
        """, (current_user.id, user_id))
        mysql.connection.commit()
        flash("Zaproszenie do znajomych zostało wysłane.", "success")
    cursor.close()
    return redirect(url_for('users'))

# Akceptowanie zaproszenia
@app.route('/accept_friend/<int:sender_id>')
@login_required
def accept_friend(sender_id):
    cursor = mysql.connection.cursor()
    cursor.execute("""
        UPDATE friends
        SET status = 'accepted'
        WHERE sender_id = %s AND receiver_id = %s
    """, (sender_id, current_user.id))
    mysql.connection.commit()
    cursor.close()
    flash("Zaproszenie zostało zaakceptowane.", "success")
    return redirect(url_for('users'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id = %s", (current_user.id,))
        data = cursor.fetchone()
        cursor.close()

        if not data:
            flash("Nie znaleziono użytkownika.", "danger")
            return redirect(url_for('home'))

        stored_hash = data[0]
        if not check_password_hash(stored_hash, form.current_password.data):
            flash("Obecne hasło jest nieprawidłowe.", "danger")
        else:
            new_hashed = generate_password_hash(form.new_password.data)
            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hashed, current_user.id))
            mysql.connection.commit()
            cursor.close()
            flash("Hasło zostało pomyślnie zmienione.", "success")
            return redirect(url_for('profile', user_id=current_user.id))

    return render_template('change_password.html', form=form)

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id, review_id FROM comments WHERE id = %s", (comment_id,))
    comment = cursor.fetchone()

    if not comment:
        flash("Nie znaleziono komentarza.", "warning")
        return redirect(url_for('home'))

    if comment[0] != current_user.id and not current_user.is_admin:
        flash("Nie możesz usunąć tego komentarza.", "danger")
        return redirect(url_for('home'))

    cursor.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
    mysql.connection.commit()
    flash("Komentarz został usunięty.", "info")
    return redirect(request.referrer or url_for('home'))

@app.route('/propose_album', methods=['GET', 'POST'])
@login_required
def propose_album():
    form = AlbumProposalForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO pending_albums (title, artist, genre, release_date, cover_url, submitted_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            form.title.data, form.artist.data, form.genre.data,
            form.release_date.data, form.cover_url.data, current_user.id
        ))
        mysql.connection.commit()
        flash('Propozycja albumu została przesłana! Oczekuje na zatwierdzenie przez administratora.', 'info')
        return redirect(url_for('home'))
    return render_template('propose_album.html', form=form)

@app.route('/admin/album_proposals')
@login_required
def album_proposals():
    if not current_user.is_admin:
        abort(403)
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, title, artist, genre, release_date, cover_url, submitted_by FROM pending_albums
        ORDER BY created_at DESC
    """)
    proposals = cursor.fetchall()
    return render_template('album_proposals.html', proposals=proposals)

@app.route('/admin/approve_album/<int:proposal_id>', methods=['POST'])
@login_required
def approve_album(proposal_id):
    if not current_user.is_admin:
        abort(403)
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT title, artist, genre, release_date, cover_url FROM pending_albums WHERE id = %s", (proposal_id,))
    album = cursor.fetchone()
    if album:
        cursor.execute("""
            INSERT INTO albums (title, artist, genre, release_date, cover_url)
            VALUES (%s, %s, %s, %s, %s)
        """, album)
        cursor.execute("DELETE FROM pending_albums WHERE id = %s", (proposal_id,))
        mysql.connection.commit()
        flash('Album został zatwierdzony i dodany do listy!', 'success')
    return redirect(url_for('album_proposals'))


@app.route('/admin/reject_album/<int:proposal_id>', methods=['POST'])
@login_required
def reject_album(proposal_id):
    if not current_user.is_admin:
        abort(403)
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM pending_albums WHERE id = %s", (proposal_id,))
    mysql.connection.commit()
    flash('Propozycja albumu została odrzucona i usunięta.', 'warning')
    return redirect(url_for('album_proposals'))

@app.route('/like_album/<int:album_id>', methods=['POST'])
@login_required
def like_album(album_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM liked_albums WHERE user_id = %s AND album_id = %s", (current_user.id, album_id))
    if cursor.fetchone():
        cursor.execute("DELETE FROM liked_albums WHERE user_id = %s AND album_id = %s", (current_user.id, album_id))
    else:
        cursor.execute("INSERT INTO liked_albums (user_id, album_id) VALUES (%s, %s)", (current_user.id, album_id))
    mysql.connection.commit()
    return redirect(request.referrer)

@app.route('/toggle_listen_later/<int:album_id>', methods=['POST'])
@login_required
def toggle_listen_later(album_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM to_listen_albums WHERE user_id = %s AND album_id = %s", (current_user.id, album_id))
    if cursor.fetchone():
        cursor.execute("DELETE FROM to_listen_albums WHERE user_id = %s AND album_id = %s", (current_user.id, album_id))
    else:
        cursor.execute("INSERT INTO to_listen_albums (user_id, album_id) VALUES (%s, %s)", (current_user.id, album_id))
    mysql.connection.commit()
    return redirect(request.referrer)
