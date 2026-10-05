# ShopFlow RDC

Prototype web avec backend Node.js local et base SQLite.

## Démarrer en local

1. Dans un terminal ouvert dans `ShopFlow-RDC`, exécuter `npm start`.
2. Ouvrir <http://localhost:3000>.
3. La base SQLite est créée dans `../ShopFlow-RDC-data/shopflow.sqlite`, hors du dossier servi par le site.

L’inscription reste volontairement désactivée tant que l’envoi Gmail n’est pas configuré. Aucun compte en attente ne peut se connecter avant l’approbation du créateur.

## Configurer les e-mails Gmail

1. Le compte Gmail d’envoi est `safarinamegabebonc@gmail.com`.
2. Activer la validation en deux étapes sur ce compte Google.
3. Créer un mot de passe d’application Gmail dans la sécurité du compte Google.
4. Ouvrir le fichier local `.env` dans VS Code et saisir ce mot de passe uniquement après `SMTP_APP_PASSWORD=`. Ne pas le partager dans une conversation, un dépôt ou une capture d’écran.
5. Arrêter puis redémarrer le serveur avec `npm start`.

À chaque nouvelle inscription, un lien d’approbation unique valable 24 heures sera envoyé à `ADMIN_EMAIL`. L’approbation ou le refus entraîne un e-mail au demandeur. L’inscription utilise SMTP; le formulaire public de contact peut utiliser Web3Forms.

## Configurer Web3Forms pour le formulaire de contact

1. Créer une Access Key depuis le tableau de bord Web3Forms et vérifier l’adresse de réception configurée pour cette clé.
2. Dans le fichier local `.env`, ajouter `WEB3FORMS_ACCESS_KEY=` suivi de la clé. Ne pas la mettre dans `index.html`, `.env.example`, un dépôt public ou une conversation.
3. Redémarrer le serveur avec `npm start`.

Le formulaire de contact enverra le nom, l’adresse e-mail, le sujet et le message via Web3Forms. Les mots de passe ne sont jamais transmis à ce service. La création et l’approbation de comptes continuent d’utiliser les e-mails SMTP Gmail configurés ci-dessus.

## Sécurité et limites

- Les mots de passe ne sont jamais stockés en clair. Le serveur conserve uniquement un vérificateur dérivé par scrypt avec sel.
- Les sessions utilisent un cookie HttpOnly, SameSite=Lax ; les jetons sont conservés hachés en base.
- Les boutiques, produits et ventes sont persistés dans SQLite et filtrés par propriétaire côté serveur.
- Ce serveur est prévu pour un essai local. Ne pas le publier sur Internet sans HTTPS, sauvegardes, politique de confidentialité, contrôles de sécurité supplémentaires et configuration de déploiement adaptée.
- Le mot de passe d’application Gmail est un secret d’envoi d’e-mail ; il ne permet pas de lire la boîte Gmail. Révoque-le depuis les paramètres Google si nécessaire.
