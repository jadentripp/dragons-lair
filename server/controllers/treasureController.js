module.exports={
    dragonTreasure: async (req,res)=>{
        const db = req.app.get('db')
        const treasure = await db.get_dragon_treasure(1)
        return res.status(200).send(treasure)
    }
}