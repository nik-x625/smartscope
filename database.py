from datetime import datetime
from bson import ObjectId
from flask_pymongo import PyMongo

# Create a global MongoDB instance
mongo = PyMongo()

class DatabaseService:
    def __init__(self, mongo_instance):
        self.db = mongo_instance.db

    def get_all_templates(self):
        """Get all templates sorted by creation date"""
        return list(self.db.templates.find().sort('created_at', -1))

    def create_template(self, template_data):
        """Create a new template"""
        template_data.update({
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })
        result = self.db.templates.insert_one(template_data)
        return result.inserted_id

    def get_chapters(self):
        """Get all chapters"""
        return list(self.db.chapters.find())

    def get_chapter(self, chapter_id):
        """Get a single chapter by ID"""
        return self.db.chapters.find_one({'_id': ObjectId(chapter_id)})

    def create_chapter(self, title):
        """Create a new chapter"""
        result = self.db.chapters.insert_one({
            'title': title,
            'paragraphs': []
        })
        return self.db.chapters.find_one({'_id': result.inserted_id})

    def update_chapter(self, chapter_id, title):
        """Update a chapter's title"""
        result = self.db.chapters.update_one(
            {'_id': ObjectId(chapter_id)},
            {'$set': {'title': title}}
        )
        return result.modified_count > 0

    def update_chapter_order(self, chapter_ids):
        """Update chapter order"""
        for index, chapter_id in enumerate(chapter_ids):
            self.db.chapters.update_one(
                {'_id': ObjectId(chapter_id)},
                {'$set': {'order': index}}
            )
        return list(self.db.chapters.find().sort('order', 1))

    def delete_chapter(self, chapter_id):
        """Delete a chapter"""
        return self.db.chapters.delete_one({'_id': ObjectId(chapter_id)})

    def add_paragraph(self, chapter_id, content):
        """Add a paragraph to a chapter"""
        return self.db.chapters.update_one(
            {'_id': ObjectId(chapter_id)},
            {'$push': {'paragraphs': {'content': content}}}
        )

    def update_paragraph(self, chapter_id, paragraph_index, content):
        """Update a paragraph in a chapter"""
        return self.db.chapters.update_one(
            {'_id': ObjectId(chapter_id)},
            {'$set': {f'paragraphs.{paragraph_index}.content': content}}
        )

    def delete_paragraph(self, chapter_id, paragraph_index):
        """Delete a paragraph from a chapter"""
        return self.db.chapters.update_one(
            {'_id': ObjectId(chapter_id)},
            {'$unset': {f'paragraphs.{paragraph_index}': ""}}
        ) 