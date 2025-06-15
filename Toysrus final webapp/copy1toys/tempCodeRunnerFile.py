
@app.route('/delete_qna', methods=['POST'])
def delete_qna():
    if 'user_id' not in session:
        flash("You need to be logged in to delete a QnA.", "danger")
        return redirect(url_for('login'))

    user_id = str(session['user_id'])
    user_email = session.get('user_email')
    toy_id = request.form.get('toy_id')  # Get `toy_id` from form
    qna_id = request.form.get('qna_id')  # Get `qna_id` from form

    # Debugging: Check if IDs are received
    print(f"DEBUG: Received toy_id -> {toy_id}, qna_id -> {qna_id}")
    print(f"DEBUG: Logged-in user_id -> {user_id}, user_email -> {user_email}")

    if not toy_id or not qna_id:
        flash("Error: Missing toy ID or QnA ID.", "danger")
        return redirect(url_for('retrieve_qna', toy_id=toy_id))

    try:
        qna_id = int(qna_id)  # Ensure qna_id is an integer
    except ValueError:
        flash("Invalid QnA ID.", "danger")
        return redirect(url_for('retrieve_qna', toy_id=toy_id))

    with shelve.open('qna.db', 'c') as db:
        qna_dict = db.get('QnA', {})  # Retrieve existing QnAs safely

        print(f"DEBUG: Existing QnA keys -> {list(qna_dict.keys())}")

        if qna_id not in qna_dict:
            flash("QnA not found.", "danger")
            return redirect(url_for('retrieve_qna', toy_id=toy_id))

        qna_entry = qna_dict[qna_id]

        # Allow delete if user is author or admin
        if str(qna_entry.get_user_id()) == user_id or user_email in ["bobby24@mytoysrus.com", "daeho388@mytoysrus.com"]:
            print(f"DEBUG: Deleting QnA with key {qna_id}")
            del qna_dict[qna_id]

            # Save only if QnA dictionary is NOT empty
            if qna_dict:
                db['QnA'] = qna_dict  # Correctly update shelve
            else:
                del db['QnA']  # Delete QnA entry if it's empty to prevent errors

            flash("QnA deleted successfully!", "success")
        else:
            flash("You do not have permission to delete this QnA.", "danger")

    return redirect(url_for('retrieve_qna', toy_id=toy_id))  # Stay on toy details page
